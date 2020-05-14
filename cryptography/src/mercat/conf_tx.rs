// TODO check rust guideline for what needs prefixing when importing and calling methods vs calling structs
use crate::{
    asset_proofs::{
        ciphertext_refreshment_proof::CipherTextRefreshmentProverAwaitingChallenge,
        ciphertext_refreshment_proof::CipherTextRefreshmentVerifier, encrypt_using_two_pub_keys,
        encrypting_same_value_proof::EncryptingSameValueProverAwaitingChallenge,
        encrypting_same_value_proof::EncryptingSameValueVerifier,
        encryption_proofs::single_property_prover, encryption_proofs::single_property_verifier,
        range_proof::prove_within_range, range_proof::verify_within_range, CommitmentWitness,
    },
    errors::{ErrorKind, Fallible},
    mercat::{
        CipherEqualDifferentPubKeyProof, CipherEqualSamePubKeyProof,
        ConfidentialTransactionReceiver, ConfidentialTransactionSender, ConfidentialTxMemo,
        ConfidentialTxState, EncryptedAssetId, EncryptionKeys, EncryptionPubKey, EncryptionSecKey,
        InRangeProof, PubAccount, PubFinalConfidentialTxData, PubInitConfidentialTxData, Signature,
        SignatureSecKey, TxSubstate,
    },
};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::StdRng;
use std::convert::TryFrom;
use zeroize::Zeroizing;

// ------------------------------------------------------------------------------------------------
// -                                          Sender                                            -
// ------------------------------------------------------------------------------------------------

/// The sender of a confidential transaction. Sender creates a transaction
/// and performs initial proofs.
pub struct CtxSender {}

impl ConfidentialTransactionSender for CtxSender {
    fn create(
        &self,
        sndr_enc_keys: EncryptionKeys,
        sndr_sign_key: SignatureSecKey,
        sndr_account: PubAccount,
        rcvr_pub_key: EncryptionPubKey,
        rcvr_account: PubAccount,
        asset_id: u32,
        amount: u32,
        rng: &mut StdRng,
    ) -> Fallible<(PubInitConfidentialTxData, ConfidentialTxState)> {
        let range = 32;
        // Prove that the amount encrypted under different public keys are the same
        let witness = CommitmentWitness::try_from((amount, Scalar::random(rng)))?;
        let amount_enc_blinding = *witness.blinding();
        let (sndr_new_enc_amount, rcvr_new_enc_amount) =
            encrypt_using_two_pub_keys(&witness, sndr_enc_keys.pblc.key, rcvr_pub_key.key);

        let amount_equal_cipher_proof =
            CipherEqualDifferentPubKeyProof::new(single_property_prover(
                EncryptingSameValueProverAwaitingChallenge {
                    pub_key1: sndr_enc_keys.pblc.key,
                    pub_key2: rcvr_pub_key.key,
                    w: Zeroizing::new(witness.clone()),
                },
                rng,
            )?);

        // Prove that committed amount is not negative
        let non_neg_amount_proof = InRangeProof {
            proof: prove_within_range(amount.into(), amount_enc_blinding, range)?.0,
            commitment: sndr_new_enc_amount.y.compress(),
            range: range,
        };

        // Refresh the encrypted balance and prove that the refreshment was done
        // correctly
        let balance_refresh_enc_blinding = Scalar::random(rng);
        let refreshed_enc_balance = sndr_account
            .enc_balance
            .refresh(&sndr_enc_keys.scrt.key, balance_refresh_enc_blinding)?;
        let balance_refreshed_same_proof = CipherEqualSamePubKeyProof::new(single_property_prover(
            CipherTextRefreshmentProverAwaitingChallenge::new(
                sndr_enc_keys.scrt.key.clone(),
                sndr_account.enc_balance,
                refreshed_enc_balance,
            ),
            rng,
        )?);

        // Prove that sender has enough funds
        // NOTE: If this decryption ends up being too slow, we can pass in the balance
        // as input.
        let balance = sndr_enc_keys.scrt.key.decrypt(&sndr_account.enc_balance)?;
        // TODO: does the blinding have to be the same as the one used in encryption?
        //let blinding = refreshed_enc_balance
        let blinding = balance_refresh_enc_blinding - amount_enc_blinding;
        let enough_fund_commitment = refreshed_enc_balance.y - sndr_new_enc_amount.y;
        let enough_fund_proof = InRangeProof {
            proof: prove_within_range((balance - amount).into(), blinding, range)?.0,
            commitment: enough_fund_commitment.compress(),
            range: range,
        };

        // Prove that the encrytped asset id is the same
        let enc_asset_id_using_rcvr = rcvr_pub_key.key.encrypt_value(asset_id)?;
        // TODO: what is the blinding value here?
        let blinding = Scalar::random(rng);
        let asset_id_equal_cipher_proof =
            CipherEqualDifferentPubKeyProof::new(single_property_prover(
                EncryptingSameValueProverAwaitingChallenge {
                    pub_key1: sndr_enc_keys.pblc.key,
                    pub_key2: rcvr_pub_key.key,
                    w: Zeroizing::new(CommitmentWitness::try_from((balance - amount, blinding))?),
                },
                rng,
            )?);

        let memo = ConfidentialTxMemo {
            sndr_account_id: sndr_account.id,
            rcvr_account_id: rcvr_account.id,
            enc_amount_using_sndr: sndr_new_enc_amount,
            enc_amount_using_rcvr: rcvr_new_enc_amount,
            sndr_pub_key: sndr_enc_keys.pblc,
            rcvr_pub_key: rcvr_pub_key,
            enc_refreshed_balance: refreshed_enc_balance,
            enc_asset_id_using_rcvr: enc_asset_id_using_rcvr,
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
    ) -> Fallible<(PubFinalConfidentialTxData, ConfidentialTxState)> {
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
        //ensure!(false, ErrorKind::NotImplemented)
        Err(ErrorKind::NotImplemented.into())
    }
}

impl CtxReceiver {
    /// This function is called by the receiver of the transaction to finalize the
    /// transaction. It corresponds to `FinalizeCTX` function of the MERCAT paper.
    pub fn finalize_by_receiver(
        &self,
        conf_tx_init_data: PubInitConfidentialTxData,
        rcvr_enc_sec: EncryptionSecKey,
        _: SignatureSecKey,
        rcvr_account: PubAccount,
        state: ConfidentialTxState,
        expected_amount: u32,
        rng: &mut StdRng,
    ) -> Fallible<(PubFinalConfidentialTxData, ConfidentialTxState)> {
        // ensure that the previous state is correct
        match state {
            ConfidentialTxState::InitilaziationJustification(TxSubstate::Verified) => (),
            _ => return Err(ErrorKind::InvalidPreviousState { state }.into()),
        }

        // Check that amount is correct
        let received_amount = rcvr_enc_sec
            .key
            .decrypt(&conf_tx_init_data.memo.enc_amount_using_rcvr)?;

        ensure!(
            received_amount == expected_amount,
            ErrorKind::TransactionAmountMismatch {
                expected_amount,
                received_amount
            }
        );

        // Check rcvc public keys match
        let acc_key = conf_tx_init_data.memo.rcvr_pub_key.key;
        let memo_key = rcvr_account.memo.owner_pub_key.key;
        ensure!(acc_key == memo_key, ErrorKind::InputPubKeyMismatch);

        // Generate proof of equality of asset ids
        let enc_asset_id_from_sndr = conf_tx_init_data.memo.enc_asset_id_using_rcvr;
        let enc_asset_id_from_rcvr_acc = rcvr_account.enc_asset_id;
        let prover = CipherTextRefreshmentProverAwaitingChallenge::new(
            rcvr_enc_sec.key,
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

// TODO verify create transaction as well

impl CtxReceiverValidator {
    pub fn verify_finalize_by_receiver(
        &self,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        conf_tx_final_data: PubFinalConfidentialTxData,
        state: ConfidentialTxState,
    ) -> Fallible<()> {
        // ensure that the previous state is correct
        match state {
            ConfidentialTxState::Finalization(TxSubstate::Started) => (),
            _ => return Err(ErrorKind::InvalidPreviousState { state }.into()),
        }

        let memo = &conf_tx_final_data.init_data.memo;
        let init_data = &conf_tx_final_data.init_data;

        // Verify encrypted amounts are equal
        single_property_verifier(
            &EncryptingSameValueVerifier {
                pub_key1: memo.sndr_pub_key.key,
                pub_key2: memo.rcvr_pub_key.key,
                cipher1: memo.enc_amount_using_sndr,
                cipher2: memo.enc_amount_using_rcvr,
            },
            init_data.amount_equal_cipher_proof.init,
            init_data.amount_equal_cipher_proof.response,
        )?;

        // Verify that amount is not negative
        verify_within_range(
            init_data.non_neg_amount_proof.proof.clone(),
            init_data.non_neg_amount_proof.commitment,
            init_data.non_neg_amount_proof.range,
        )?;

        // verify the balance refreshment was done correctly
        // TODO: the code would have been nicer if I passed the two encrypted values
        //       instead of the diff of their xs and the diff of their ys
        single_property_verifier(
            &CipherTextRefreshmentVerifier {
                pub_key: memo.sndr_pub_key.key,
                x: sndr_account.enc_balance.x - memo.enc_refreshed_balance.x,
                y: sndr_account.enc_balance.y - memo.enc_refreshed_balance.y,
            },
            init_data.balance_refreshed_same_proof.init,
            init_data.balance_refreshed_same_proof.response,
        )?;

        // Verify that balance has enough fund
        verify_within_range(
            init_data.enough_fund_proof.proof.clone(),
            init_data.enough_fund_proof.commitment,
            init_data.enough_fund_proof.range,
        )?;

        // In the inital transaction, sender has encrypted the sset id
        // using receiver pub key.
        // In the following two sections we verify that this encrypted asset id
        // is the same as the one in the sender and receiver account

        // prove that it is the same as the one in the sender's account
        single_property_verifier(
            &EncryptingSameValueVerifier {
                pub_key1: memo.sndr_pub_key.key,
                pub_key2: memo.rcvr_pub_key.key,
                cipher1: sndr_account.enc_asset_id,
                cipher2: memo.enc_asset_id_using_rcvr,
            },
            init_data.asset_id_equal_cipher_proof.init,
            init_data.asset_id_equal_cipher_proof.response,
        )?;

        // prove that it is the same as the one in the reciever's account
        single_property_verifier(
            &CipherTextRefreshmentVerifier {
                pub_key: memo.rcvr_pub_key.key,
                x: rcvr_account.enc_asset_id.x - memo.enc_asset_id_using_rcvr.x,
                y: rcvr_account.enc_asset_id.y - memo.enc_asset_id_using_rcvr.y,
            },
            conf_tx_final_data.asset_id_equal_cipher_proof.init,
            conf_tx_final_data.asset_id_equal_cipher_proof.response,
        )?;

        // TODO verify signature of both init and finalize transactions

        Err(ErrorKind::NotImplemented.into())
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::{
        asset_proofs::{CipherText, ElgamalSecretKey},
        mercat::{
            ConfidentialTxMemo, CorrectnessProof, EncryptionKeys, EncryptionPubKey,
            EncryptionSecKey, MembershipProof, SignatureKeys, SignaturePubKey, WellformednessProof,
        },
    };
    use curve25519_dalek::scalar::Scalar;
    use rand::SeedableRng;
    use wasm_bindgen_test::*;

    // -------------------------- mock helper methods -----------------------

    fn mock_gen_enc_key_pair(seed: u8) -> EncryptionKeys {
        let mut rng = StdRng::from_seed([seed; 32]);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        EncryptionKeys {
            pblc: elg_pub.into(),
            scrt: elg_secret.into(),
        }
    }

    fn mock_gen_sign_key_pair() -> SignatureKeys {
        const SEED: [u8; 32] = [17u8; 32];
        let mut rng = StdRng::from_seed(SEED);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        SignatureKeys {
            pblc: elg_pub.into(),
            scrt: elg_secret.into(),
        }
    }

    fn mock_ctx_init_memo(
        rcvr_pub_key: EncryptionPubKey,
        amount: u32,
        asset_id: u32,
    ) -> ConfidentialTxMemo {
        let enc_amount_using_rcvr = rcvr_pub_key.key.encrypt_value(amount).unwrap();
        let enc_asset_id_using_rcvr = rcvr_pub_key.key.encrypt_value(asset_id).unwrap();

        ConfidentialTxMemo {
            sndr_account_id: 0,
            rcvr_account_id: 0,
            enc_amount_using_sndr: CipherText::default(),
            enc_amount_using_rcvr,
            sndr_pub_key: EncryptionPubKey::default(),
            rcvr_pub_key,
            enc_refreshed_balance: CipherText::default(),
            enc_asset_id_using_rcvr,
        }
    }

    fn mock_gen_account(rcvr_pub_key: EncryptionPubKey, asset_id: u32) -> Fallible<PubAccount> {
        let enc_asset_id = rcvr_pub_key.key.encrypt_value(asset_id)?;

        Ok(PubAccount {
            id: 1,
            enc_asset_id,
            enc_balance: CipherText::default(),
            asset_wellformedness_proof: WellformednessProof::default(),
            asset_membership_proof: MembershipProof::default(),
            balance_correctness_proof: CorrectnessProof::default(),
            memo: rcvr_pub_key.into(),
            sign: Signature::default(),
        })
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

        let ctx_init_data =
            mock_ctx_init_data(rcvr_enc_keys.pblc.clone(), expected_amount, asset_id);
        let rcvr_account = mock_gen_account(rcvr_enc_keys.pblc.clone(), asset_id).unwrap();
        let valid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Verified);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_enc_keys.scrt,
            rcvr_sign_keys.scrt,
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

        let ctx_init_data =
            mock_ctx_init_data(rcvr_enc_keys.pblc.clone(), expected_amount, asset_id);
        let rcvr_account = mock_gen_account(rcvr_enc_keys.pblc.clone(), asset_id).unwrap();
        let invalid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Started);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_enc_keys.scrt,
            rcvr_sign_keys.scrt,
            rcvr_account,
            invalid_state.clone(),
            expected_amount,
            &mut StdRng::from_seed([17u8; 32]),
        );

        assert_err!(
            result,
            ErrorKind::InvalidPreviousState {
                state: invalid_state,
            }
        );
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

        let ctx_init_data =
            mock_ctx_init_data(rcvr_enc_keys.pblc.clone(), received_amount, asset_id);
        let rcvr_account = mock_gen_account(rcvr_enc_keys.pblc.clone(), asset_id).unwrap();
        let valid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Verified);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_enc_keys.scrt,
            rcvr_sign_keys.scrt,
            rcvr_account,
            valid_state,
            expected_amount,
            &mut StdRng::from_seed([17u8; 32]),
        );

        assert_err!(
            result,
            ErrorKind::TransactionAmountMismatch {
                expected_amount,
                received_amount
            }
        );
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

        let ctx_init_data = mock_ctx_init_data(rcvr_enc_keys.pblc, expected_amount, asset_id);
        let rcvr_account = mock_gen_account(wrong_enc_keys.pblc, asset_id).unwrap();
        let valid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Verified);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_enc_keys.scrt,
            rcvr_sign_keys.scrt,
            rcvr_account,
            valid_state,
            expected_amount,
            &mut StdRng::from_seed([17u8; 32]),
        );

        assert_err!(result, ErrorKind::InputPubKeyMismatch);
    }
}
