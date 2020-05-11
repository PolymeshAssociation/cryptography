//! Contains the implementation of the `ConfidentialTXer` for a confidential transaction.

// TODO check rust guideline for what needs prefixing when importing and calling methods vs calling structs
use crate::asset_proofs::ciphertext_refreshment_proof::CipherTextRefreshmentProverAwaitingChallenge;
use crate::asset_proofs::encryption_proofs::single_property_prover;
use crate::mercat::errors::ConfidentialTxError;
use crate::mercat::lib::*;
use failure::Error;
use rand::{rngs::StdRng, SeedableRng};
use rand_core::{CryptoRng, RngCore};
use std::cell::Cell;

pub struct ConfTx {
    //    rng: Cell<StdRng>,
}

//impl ConfidentialTransactionReceiver for ConfTx {
//    fn finalize_and_process(
//        &self,
//        conf_tx_init_data: PubInitConfidentialTxData,
//        rcvr_enc_keys: (EncryptionPubKey, EncryptionSecKey),
//        rcvr_sign_key: SignatureSecKey,
//        sndr_pub_key: EncryptionPubKey,
//        sndr_account: PubAccount,
//        rcvr_account: PubAccount,
//        enc_asset_id: EncryptedAssetId,
//        amount: u32,
//        state: ConfidentialTxState,
//    ) -> Result<(PubFinalConfidentialTxData, ConfidentialTxState), Error> {
//        ensure!(
//            self.finalize_by_receiver(
//                conf_tx_init_data,
//                rcvr_enc_keys,
//                rcvr_sign_key,
//                sndr_pub_key,
//                sndr_account,
//                rcvr_account,
//                enc_asset_id,
//                amount,
//                state
//            ),
//            ConfidentialTxError::NotImplemented
//        );
//        ensure!(false, ConfidentialTxError::NotImplemented)
//    }
//}

impl ConfTx {
    /// This function is called by the receiver of the transaction to finalize the
    /// transaction. It corresponds to `FinalizeCTX` function of the MERCAT paper.
    pub fn finalize_by_receiver(
        &self,
        conf_tx_init_data: PubInitConfidentialTxData,
        rcvr_enc_keys: (EncryptionPubKey, EncryptionSecKey),
        rcvr_sign_key: SignatureSecKey,
        rcvr_account: PubAccount,
        state: ConfidentialTxState,
    ) -> Result<(PubFinalConfidentialTxData, ConfidentialTxState), Error> {
        // ensure that the previous state is correct
        match state {
            ConfidentialTxState::InitilaziationJustification(TxSubstate::Verified) => (),
            _ => return Err(ConfidentialTxError::InvalidPreviousState { state }.into()),
        }

        // TODO check that amount is correct
        // TODO check rcvc public key is the same as the one in the memo
        // TODO check rcvr public key is the same as the one in the account

        let enc_asset_id_from_sndr = conf_tx_init_data.memo.asset_id_enc_using_rcvr;
        let enc_asset_id_from_rcvr_acc = rcvr_account.enc_asset_id;
        // Generate proof of equality of asset ids
        let prover = CipherTextRefreshmentProverAwaitingChallenge::new(
            rcvr_enc_keys.1.key(), // convert to struct?
            enc_asset_id_from_rcvr_acc,
            enc_asset_id_from_sndr,
        );

        // I think our api should be such a bad rng such as this would still be safe
        // to pass to our api.
        const SEED: [u8; 32] = [17u8; 32];
        let mut rng = StdRng::from_seed(SEED);
        // TODO match
        match single_property_prover(prover, &mut rng) {
            Ok((initial_message, final_response)) => Ok((
                PubFinalConfidentialTxData {
                    init_data: conf_tx_init_data,
                    asset_id_equal_cipher_proof: (initial_message, final_response),
                    sig: Signature {}, // TODO: sign memo + ALL the proofs of init and final
                },
                ConfidentialTxState::Finalization(TxSubstate::Started),
            )),
            Err(err) => Err(err.into()), // TODO
        }
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::asset_proofs::{CipherText, ElgamalPublicKey, ElgamalSecretKey};
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use wasm_bindgen_test::*;

    // -------------------------- mock helper methods -----------------------

    fn mock_gen_enc_key_pair() -> (EncryptionPubKey, EncryptionSecKey) {
        const SEED: [u8; 32] = [17u8; 32];
        let mut rng = StdRng::from_seed(SEED);
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

    fn mock_ctx_init_memo(rcvr_pub_key: EncryptionPubKey) -> ConfidentialTxMemo {
        ConfidentialTxMemo {
            sndr_account_id: 0,
            rcvr_account_id: 0,
            enc_amount_using_sndr: CipherText::default(),
            enc_amount_using_rcvr: CipherText::default(),
            sndr_pub_key: EncryptionPubKey::default(),
            rcvr_pub_key: rcvr_pub_key,
            enc_refreshed_amount: CipherText::default(),
            asset_id_enc_using_rcvr: CipherText::default(),
        }
    }

    fn mock_account_memo(rcvr_pub_key: EncryptionPubKey) -> AccountMemo {
        AccountMemo {
            owner_pub_key: rcvr_pub_key,
            timestamp: std::time::Instant::now(),
        }
    }

    fn mock_gen_account(rcvr_pub_key: EncryptionPubKey) -> PubAccount {
        PubAccount {
            enc_asset_id: CipherText::default(),
            enc_balance: CipherText::default(),
            asset_wellformedness_proof: WellformednessProof::default(),
            asset_membership_proof: MembershipProof::default(),
            balance_correctness_proof: CorrectnessProof::default(),
            memo: mock_account_memo(rcvr_pub_key),
            sign: Signature::default(),
        }
    }

    // -------------------------- tests -----------------------

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_failures() {
        let ctx_rcvr = ConfTx {};

        let rcvr_enc_keys = mock_gen_enc_key_pair();
        let rcvr_sign_keys = mock_gen_sign_key_pair();

        let conf_tx_init_data = PubInitConfidentialTxData {
            memo: mock_ctx_init_memo(rcvr_enc_keys.0.clone()), // should the ".0" be changed into named fields?
            asset_id_equal_cipher_proof: CipherEqualDifferentPubKeyProof::default(),
            amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof::default(),
            non_neg_amount_proof: InRangeProof::default(),
            enough_fund_proof: InRangeProof::default(),
            sig: Signature::default(),
        };
        let rcvr_account = mock_gen_account(rcvr_enc_keys.0.clone()); // should the ".0" be changed into named fields?
        let valid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Verified);
        let invalid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Started);

        // ------------ invalid prev state
        match ctx_rcvr.finalize_by_receiver(
            conf_tx_init_data,
            rcvr_enc_keys,
            rcvr_sign_keys.1, // should the ".1" be changed into named fields?
            rcvr_account,
            invalid_state,
        ) {
            Err(e) => match e.as_fail() {
                ConfidentialTxError::InvalidPreviousState {
                    state: invalid_state,
                } => println!("aoeu"),
                _ => assert!(false, "Expected invalid previous state error, got {:?}", e),
            },
            Ok(_) => assert!(false, "Expected invalid previous state error, got Ok"),
        }
        //assert!(result.is_ok());
    }
}
