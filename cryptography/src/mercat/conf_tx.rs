//! Contains the implementation of the `ConfidentialTXer` for a confidential transaction.

// TODO check rust guideline for what needs prefixing when importing and calling methods vs calling structs
use crate::asset_proofs::ciphertext_refreshment_proof::CipherTextRefreshmentProverAwaitingChallenge;
use crate::asset_proofs::encrypting_same_value_proof::EncryptingSameValueProverAwaitingChallenge;
use crate::asset_proofs::encryption_proofs::single_property_prover;
use crate::asset_proofs::range_proof::prove_within_range;
use crate::asset_proofs::CipherText;
use crate::asset_proofs::CommitmentWitness;
use crate::mercat::errors::ConfidentialTxError;
use crate::mercat::lib::*;
use bulletproofs::PedersenGens;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use failure::Error;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::convert::TryFrom;
use zeroize::Zeroizing;

// ------------------------------------------------------------------------------------------------
// -                                          Receiver                                            -
// ------------------------------------------------------------------------------------------------

/// The sender of a confidential transaction. Sender creates a transaction
/// and performs initial proofs.
pub struct CtxSender {}

impl ConfidentialTransactionSender for CtxSender {
    fn create(
        &self,
        sndr_enc_keys: (EncryptionPubKey, EncryptionSecKey),
        sndr_sign_key: SignatureSecKey,
        sndr_account: PubAccount,
        rcvr_pub_key: EncryptionPubKey,
        rcvr_account: PubAccount,
        asset_id: u32,
        amount: u32,
        rng: &mut StdRng,
    ) -> Result<(PubInitConfidentialTxData, ConfidentialTxState), Error> {
        let range = 32;
        // Prove that the amount encrypted under different public keys are
        // the same
        // TODO: the following can become a functions in elgamal lib
        let blinding = Scalar::random(rng);
        let sndr_x = blinding * sndr_enc_keys.0.clone().key().pub_key;
        let rcvr_x = blinding * rcvr_pub_key.clone().key().pub_key;
        let gens = PedersenGens::default();
        let y = gens.commit(Scalar::from(amount), blinding);
        let sndr_new_enc_amount = CipherText { x: sndr_x, y };
        let rcvr_new_enc_amount = CipherText { x: rcvr_x, y };

        let diff_pub_key_prover = EncryptingSameValueProverAwaitingChallenge {
            pub_key1: sndr_enc_keys.0.clone().key(),
            pub_key2: rcvr_pub_key.clone().key(),
            w: Zeroizing::new(CommitmentWitness::try_from((amount, blinding))?),
        };
        let (amount_same_proof_init, amount_same_proof_response) =
            single_property_prover(diff_pub_key_prover, rng)?;
        let amount_equal_cipher_proof = CipherEqualDifferentPubKeyProof {
            init: amount_same_proof_init,
            response: amount_same_proof_response,
        };

        // Prove that committed amount is not negative
        // Note that the second part of the proof should be the encrypted amount
        // which is computed above
        // TODO: since our usecase is to do rangeproof on encrypted values,
        //       I think we can create a simler helper function in range proof lib
        // TODO: does the blinding have to be the same as the one used in encryption?
        let (non_neg_amount_proof, _) = prove_within_range(amount.into(), blinding, range)?;
        let non_neg_amount_proof = InRangeProof {
            proof: non_neg_amount_proof,
            commitment: y.compress(),
            range: range,
        };

        // Refresh the encrypted balance and prove that the refreshment was done
        // correctly
        let refreshed_enc_balance = sndr_account
            .enc_balance
            // TODO: I suggest renaming this method to "refresh"
            .ciphertext_refreshment_method(&sndr_enc_keys.1.clone().key(), rng)?;
        let ciphertext_refresh_prover = CipherTextRefreshmentProverAwaitingChallenge::new(
            sndr_enc_keys.1.clone().key(),
            sndr_account.enc_balance,
            refreshed_enc_balance,
        );
        let (balance_same_proof_init, balance_same_proof_response) =
            single_property_prover(ciphertext_refresh_prover, rng)?;
        let balance_refreshed_same_proof = CipherEqualSamePubKeyProof {
            init: balance_same_proof_init,
            response: balance_same_proof_response,
        };

        // Prove that sender has enough funds
        // NOTE: If this decryption ends up being too slow, we can pass in the balance
        // as input.
        let balance = sndr_enc_keys.1.key().decrypt(&sndr_account.enc_balance)?;
        // TODO: does the blinding have to be the same as the one used in encryption?
        let blinding = Scalar::random(rng);
        let enough_fund_commitment = refreshed_enc_balance.y - y;
        let (enough_fund_proof, _) =
            prove_within_range((balance - amount).into(), blinding, range)?;
        let enough_fund_proof = InRangeProof {
            proof: enough_fund_proof,
            commitment: enough_fund_commitment.compress(),
            range: range,
        };

        // Prove that the encrytped asset id is the same
        let enc_asset_id_using_receiver = rcvr_pub_key.clone().key().encrypt_value(asset_id)?;
        // TODO: what is the blinding value here?
        let blinding = Scalar::random(rng);
        let diff_pub_key_prover = EncryptingSameValueProverAwaitingChallenge {
            pub_key1: sndr_enc_keys.0.clone().key(),
            pub_key2: rcvr_pub_key.clone().key(),
            w: Zeroizing::new(CommitmentWitness::try_from((balance - amount, blinding))?),
        };
        let (asset_same_proof_init, asset_same_proof_response) =
            single_property_prover(diff_pub_key_prover, rng)?;
        let asset_id_equal_cipher_proof = CipherEqualDifferentPubKeyProof {
            init: asset_same_proof_init,
            response: asset_same_proof_response,
        };

        let memo = ConfidentialTxMemo {
            sndr_account_id: sndr_account.id,
            rcvr_account_id: rcvr_account.id,
            enc_amount_using_sndr: sndr_new_enc_amount,
            enc_amount_using_rcvr: rcvr_new_enc_amount,
            sndr_pub_key: sndr_enc_keys.0,
            rcvr_pub_key: rcvr_pub_key,
            enc_refreshed_balance: refreshed_enc_balance,
            enc_asset_id_using_rcvr: enc_asset_id_using_receiver,
        };
        // TODO: sign memo and all the five proofs
        let sig = Signature {};

        let init_data = PubInitConfidentialTxData {
            amount_equal_cipher_proof: amount_equal_cipher_proof,
            non_neg_amount_proof: non_neg_amount_proof,
            enough_fund_proof: enough_fund_proof,
            memo: memo,
            asset_id_equal_cipher_proof: asset_id_equal_cipher_proof,
            balance_refreshed_same_proof: balance_refreshed_same_proof,
            sig: sig,
        };
        Ok((
            init_data,
            ConfidentialTxState::Initialization(TxSubstate::Started),
        ))
    }
}
// ------------------------------------------------------------------------------------------------
// -                                          Receiver                                            -
// ------------------------------------------------------------------------------------------------

/// The receiver of a confidential transaction. Receiver finalizes and processes
/// transaction.
pub struct CtxReceiver {}

impl ConfidentialTransactionReceiver for CtxReceiver {
    fn finalize_and_process(
        &self,
        conf_tx_init_data: PubInitConfidentialTxData,
        rcvr_enc_keys: (EncryptionPubKey, EncryptionSecKey),
        rcvr_sign_key: SignatureSecKey,
        sndr_pub_key: EncryptionPubKey,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        enc_asset_id: EncryptedAssetId,
        amount: u32,
        state: ConfidentialTxState,
        rng: &mut StdRng,
    ) -> Result<(PubFinalConfidentialTxData, ConfidentialTxState), Error> {
        self.finalize_by_receiver(
            conf_tx_init_data,
            rcvr_enc_keys.1,
            rcvr_sign_key,
            rcvr_account,
            state,
            amount,
            rng,
        )?;

        // TODO: will complete this in the ctx processing story
        //ensure!(false, ConfidentialTxError::NotImplemented)
        Err(ConfidentialTxError::NotImplemented.into())
    }
}

impl CtxReceiver {
    /// This function is called by the receiver of the transaction to finalize the
    /// transaction. It corresponds to `FinalizeCTX` function of the MERCAT paper.
    pub fn finalize_by_receiver(
        &self,
        conf_tx_init_data: PubInitConfidentialTxData,
        rcvr_enc_sec: EncryptionSecKey,
        rcvr_sign_key: SignatureSecKey,
        rcvr_account: PubAccount,
        state: ConfidentialTxState,
        expected_amount: u32,
        rng: &mut StdRng,
    ) -> Result<(PubFinalConfidentialTxData, ConfidentialTxState), Error> {
        // ensure that the previous state is correct
        match state {
            ConfidentialTxState::InitilaziationJustification(TxSubstate::Verified) => (),
            _ => return Err(ConfidentialTxError::InvalidPreviousState { state }.into()),
        }

        // Check that amount is correct
        let received_amount = rcvr_enc_sec
            .clone()
            .key()
            .decrypt(&conf_tx_init_data.memo.enc_amount_using_rcvr)?;

        ensure!(
            received_amount == expected_amount,
            ConfidentialTxError::TransactionAmountMismatch {
                expected_amount,
                received_amount
            }
        );

        // Check rcvc public keys match
        let acc_key = conf_tx_init_data.memo.rcvr_pub_key.clone().key();
        let memo_key = rcvr_account.memo.owner_pub_key.key();
        ensure!(
            acc_key == memo_key,
            ConfidentialTxError::InputPubKeyMismatch
        );

        // Generate proof of equality of asset ids
        let enc_asset_id_from_sndr = conf_tx_init_data.memo.enc_asset_id_using_rcvr;
        let enc_asset_id_from_rcvr_acc = rcvr_account.enc_asset_id;
        let prover = CipherTextRefreshmentProverAwaitingChallenge::new(
            rcvr_enc_sec.key(),
            enc_asset_id_from_rcvr_acc,
            enc_asset_id_from_sndr,
        );

        single_property_prover(prover, rng).and_then(|(init, response)| {
            Ok((
                PubFinalConfidentialTxData {
                    init_data: conf_tx_init_data,
                    asset_id_equal_cipher_proof: CipherEqualSamePubKeyProof { init, response },
                    sig: Signature {}, // TODO: sign memo + ALL the proofs of init and final
                },
                ConfidentialTxState::Finalization(TxSubstate::Started),
            ))
        })
    }
}

// ------------------------------------------------------------------------------------------------
// -                                          Validator                                           -
// ------------------------------------------------------------------------------------------------

/// Verifies the the proofs that that are performed by both the Sender and the Receiver of a
/// confidential transaction.
pub struct CtxReceiverValidator {}

//impl ConfidentialTransactionFinalizeAndProcessVerifier for CtxReceiverValidator {
//    fn verify(
//        &self,
//        sndr_account: PubAccount,
//        rcvr_account: PubAccount,
//        rcvr_sign_pub_key: SignaturePubKey,
//        conf_tx_final_data: PubFinalConfidentialTxData,
//        state: ConfidentialTxState,
//    ) -> Result<ConfidentialTxState, Error> {
//    }
//}

impl CtxReceiverValidator {
    pub fn verify_finalize_by_receiver(
        &self,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        conf_tx_final_data: PubFinalConfidentialTxData,
        state: ConfidentialTxState,
    ) {
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::asset_proofs::{CipherText, ElgamalSecretKey};
    use curve25519_dalek::scalar::Scalar;
    use wasm_bindgen_test::*;

    // -------------------------- mock helper methods -----------------------

    fn mock_gen_enc_key_pair(seed: u8) -> (EncryptionPubKey, EncryptionSecKey) {
        let mut rng = StdRng::from_seed([seed; 32]);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        (EncryptionPubKey(elg_pub), EncryptionSecKey(elg_secret))
    }

    fn mock_gen_sign_key_pair() -> (SignaturePubKey, SignatureSecKey) {
        const SEED: [u8; 32] = [17u8; 32];
        let mut rng = StdRng::from_seed(SEED);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        (SignaturePubKey(elg_pub), SignatureSecKey(elg_secret))
    }

    fn mock_ctx_init_memo(
        rcvr_pub_key: EncryptionPubKey,
        amount: u32,
        asset_id: u32,
    ) -> ConfidentialTxMemo {
        ConfidentialTxMemo {
            sndr_account_id: 0,
            rcvr_account_id: 0,
            enc_amount_using_sndr: CipherText::default(),
            enc_amount_using_rcvr: rcvr_pub_key.clone().key().encrypt_value(amount).unwrap(),
            sndr_pub_key: EncryptionPubKey::default(),
            rcvr_pub_key: rcvr_pub_key.clone(),
            enc_refreshed_balance: CipherText::default(),
            enc_asset_id_using_rcvr: rcvr_pub_key.key().encrypt_value(asset_id).unwrap(),
        }
    }

    fn mock_account_memo(rcvr_pub_key: EncryptionPubKey) -> AccountMemo {
        AccountMemo {
            owner_pub_key: rcvr_pub_key,
            timestamp: std::time::Instant::now(),
        }
    }

    fn mock_gen_account(rcvr_pub_key: EncryptionPubKey, asset_id: u32) -> PubAccount {
        PubAccount {
            id: 1,
            enc_asset_id: rcvr_pub_key.clone().key().encrypt_value(asset_id).unwrap(),
            enc_balance: CipherText::default(),
            asset_wellformedness_proof: WellformednessProof::default(),
            asset_membership_proof: MembershipProof::default(),
            balance_correctness_proof: CorrectnessProof::default(),
            memo: mock_account_memo(rcvr_pub_key),
            sign: Signature::default(),
        }
    }

    fn mock_ctx_init_data(
        rcvr_pub_key: EncryptionPubKey,
        expected_amount: u32,
        asset_id: u32,
    ) -> PubInitConfidentialTxData {
        PubInitConfidentialTxData {
            memo: mock_ctx_init_memo(rcvr_pub_key, expected_amount, asset_id),
            asset_id_equal_cipher_proof: CipherEqualDifferentPubKeyProof::default(),
            amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof::default(),
            non_neg_amount_proof: InRangeProof::default(),
            enough_fund_proof: InRangeProof::default(),
            balance_refreshed_same_proof: CipherEqualSamePubKeyProof::default(),
            sig: Signature::default(),
        }
    }

    // -------------------------- tests -----------------------

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_success() {
        let ctx_rcvr = CtxReceiver {};
        let expected_amount = 10;
        let asset_id = 20;

        let rcvr_enc_keys = mock_gen_enc_key_pair(17u8);
        let rcvr_sign_keys = mock_gen_sign_key_pair();

        let ctx_init_data = mock_ctx_init_data(rcvr_enc_keys.0.clone(), expected_amount, asset_id); // should the ".0" be changed into named fields?
        let rcvr_account = mock_gen_account(rcvr_enc_keys.0.clone(), asset_id); // should the ".0" be changed into named fields?
        let valid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Verified);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_enc_keys.1,
            rcvr_sign_keys.1, // should the ".1" be changed into named fields?
            rcvr_account,
            valid_state,
            expected_amount,
            &mut StdRng::from_seed([17u8; 32]),
        );

        match result {
            Err(e) => assert!(false, "{:?}", e),
            _ => (),
        }
        // Correctness of the proof will be verified in the verify function
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_prev_state_error() {
        let ctx_rcvr = CtxReceiver {};
        let expected_amount = 10;
        let asset_id = 20;

        let rcvr_enc_keys = mock_gen_enc_key_pair(17u8);
        let rcvr_sign_keys = mock_gen_sign_key_pair();

        let ctx_init_data = mock_ctx_init_data(rcvr_enc_keys.0.clone(), expected_amount, asset_id); // should the ".0" be changed into named fields?
        let rcvr_account = mock_gen_account(rcvr_enc_keys.0.clone(), asset_id); // should the ".0" be changed into named fields?
        let invalid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Started);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_enc_keys.1,
            rcvr_sign_keys.1, // should the ".1" be changed into named fields?
            rcvr_account,
            invalid_state.clone(),
            expected_amount,
            &mut StdRng::from_seed([17u8; 32]),
        );

        match result {
            Err(e) => assert_eq!(
                e.downcast::<ConfidentialTxError>().unwrap(),
                ConfidentialTxError::InvalidPreviousState {
                    state: invalid_state,
                }
            ),
            _ => assert!(false, "Expected error, got OK!"),
        }
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_amount_mismatch_error() {
        let ctx_rcvr = CtxReceiver {};
        let expected_amount = 10;
        let received_amount = 20;
        let asset_id = 20;

        let rcvr_enc_keys = mock_gen_enc_key_pair(17u8);
        let rcvr_sign_keys = mock_gen_sign_key_pair();

        let ctx_init_data = mock_ctx_init_data(rcvr_enc_keys.0.clone(), received_amount, asset_id); // should the ".0" be changed into named fields?
        let rcvr_account = mock_gen_account(rcvr_enc_keys.0.clone(), asset_id); // should the ".0" be changed into named fields?
        let valid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Verified);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_enc_keys.1,
            rcvr_sign_keys.1, // should the ".1" be changed into named fields?
            rcvr_account,
            valid_state,
            expected_amount,
            &mut StdRng::from_seed([17u8; 32]),
        );

        match result {
            Err(e) => assert_eq!(
                e.downcast::<ConfidentialTxError>().unwrap(),
                ConfidentialTxError::TransactionAmountMismatch {
                    expected_amount,
                    received_amount
                },
            ),
            _ => assert!(false, "Expected error, got OK!"),
        }
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_pub_key_mismatch_error() {
        let ctx_rcvr = CtxReceiver {};
        let expected_amount = 10;
        let asset_id = 20;

        let rcvr_enc_keys = mock_gen_enc_key_pair(17u8);
        let wrong_enc_keys = mock_gen_enc_key_pair(18u8);
        let rcvr_sign_keys = mock_gen_sign_key_pair();

        let ctx_init_data = mock_ctx_init_data(rcvr_enc_keys.0.clone(), expected_amount, asset_id); // should the ".0" be changed into named fields?
        let rcvr_account = mock_gen_account(wrong_enc_keys.0.clone(), asset_id); // should the ".0" be changed into named fields?
        let valid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Verified);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_enc_keys.1,
            rcvr_sign_keys.1, // should the ".1" be changed into named fields?
            rcvr_account,
            valid_state,
            expected_amount,
            &mut StdRng::from_seed([17u8; 32]),
        );

        match result {
            Err(e) => assert_eq!(
                e.downcast::<ConfidentialTxError>().unwrap(),
                ConfidentialTxError::InputPubKeyMismatch,
            ),
            _ => assert!(false, "Expected error, got OK!"),
        }
    }
}
