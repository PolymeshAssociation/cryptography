//! Contains the implementation of the `ConfidentialTXer` for a confidential transaction.

// TODO check rust guideline for what needs prefixing when importing and calling methods vs calling structs
use crate::asset_proofs::ciphertext_refreshment_proof::CipherTextRefreshmentProverAwaitingChallenge;
use crate::asset_proofs::encryption_proofs::single_property_prover;
use crate::mercat::errors::ConfidentialTxError;
use crate::mercat::lib::*;
use failure::Error;
use rand::{rngs::StdRng, SeedableRng};

pub struct ConfTx {}

impl ConfidentialTransactionReceiver for ConfTx {
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
    ) -> Result<(PubFinalConfidentialTxData, ConfidentialTxState), Error> {
        self.finalize_by_receiver(
            conf_tx_init_data,
            rcvr_enc_keys.1,
            rcvr_sign_key,
            rcvr_account,
            state,
            amount,
        )?;

        // TODO: will complete this in the ctx processing story
        //ensure!(false, ConfidentialTxError::NotImplemented)
        Err(ConfidentialTxError::NotImplemented.into())
    }
}

impl ConfTx {
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

        // TODO: I think our api should be such that a bad rng such as the following would still be safe
        // to pass to our api.
        // Another story will address removing this rng althogether
        const SEED: [u8; 32] = [17u8; 32];
        let mut rng = StdRng::from_seed(SEED);
        single_property_prover(prover, &mut rng).and_then(|(initial_message, final_response)| {
            Ok((
                PubFinalConfidentialTxData {
                    init_data: conf_tx_init_data,
                    asset_id_equal_cipher_proof: (initial_message, final_response),
                    sig: Signature {}, // TODO: sign memo + ALL the proofs of init and final
                },
                ConfidentialTxState::Finalization(TxSubstate::Started),
            ))
        })
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
            enc_refreshed_amount: CipherText::default(),
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
            sig: Signature::default(),
        }
    }

    // -------------------------- tests -----------------------

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_success() {
        let ctx_rcvr = ConfTx {};
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
        let ctx_rcvr = ConfTx {};
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
        let ctx_rcvr = ConfTx {};
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
        let ctx_rcvr = ConfTx {};
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
