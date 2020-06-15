use crate::{
    asset_proofs::{
        ciphertext_refreshment_proof::CipherTextRefreshmentProverAwaitingChallenge,
        ciphertext_refreshment_proof::CipherTextRefreshmentVerifier,
        encrypt_using_two_pub_keys,
        encrypting_same_value_proof::EncryptingSameValueProverAwaitingChallenge,
        encrypting_same_value_proof::EncryptingSameValueVerifier,
        encryption_proofs::single_property_prover,
        encryption_proofs::single_property_verifier,
        range_proof::{prove_within_range, verify_within_range},
        CommitmentWitness,
    },
    errors::{ErrorKind, Fallible},
    mercat::{
        Account, CipherEqualDifferentPubKeyProof, CipherEqualSamePubKeyProof,
        ConfidentialTransactionInitVerifier, ConfidentialTransactionReceiver,
        ConfidentialTransactionSender, ConfidentialTxMemo, ConfidentialTxState, EncryptedAssetId,
        InRangeProof, PubAccount, PubFinalConfidentialTxData, PubFinalConfidentialTxDataContent,
        PubInitConfidentialTxData, PubInitConfidentialTxDataContent, TxSubstate,
    },
    Balance, BALANCE_RANGE,
};

use bulletproofs::PedersenGens;
use curve25519_dalek::scalar::Scalar;
use lazy_static::lazy_static;
use rand::rngs::StdRng;
use rand_core::OsRng;
use schnorrkel::{context::SigningContext, signing_context};
use zeroize::Zeroizing;

lazy_static! {
    static ref SIG_CTXT: SigningContext = signing_context(b"mercat/conf_tx");
}

// -------------------------------------------------------------------------------------
// -                                    Sender                                         -
// -------------------------------------------------------------------------------------

/// The sender of a confidential transaction. Sender creates a transaction
/// and performs initial proofs.
pub struct CtxSender {}

impl ConfidentialTransactionSender for CtxSender {
    fn create(
        &self,
        sndr_account: &Account,
        rcvr_pub_account: &PubAccount,
        amount: Balance,
        rng: &mut StdRng,
    ) -> Fallible<(PubInitConfidentialTxData, ConfidentialTxState)> {
        let gens = PedersenGens::default();
        // NOTE: If this decryption ends up being too slow, we can pass in the balance
        // as input.
        let sndr_enc_keys = &sndr_account.scrt.enc_keys;
        let sndr_sign_keys = &sndr_account.scrt.sign_keys;
        let asset_id = sndr_account.scrt.asset_id.clone();
        let sndr_pub_account = &sndr_account.pblc.content;
        let rcvr_pub_account = &rcvr_pub_account.content;
        let rcvr_pub_key = rcvr_pub_account.memo.owner_enc_pub_key;

        let balance = sndr_enc_keys
            .scrt
            .decrypt(&sndr_pub_account.enc_balance.cipher)?;
        ensure!(
            balance >= amount,
            ErrorKind::NotEnoughFund {
                balance,
                transaction_amount: amount
            }
        );

        // Prove that the amount is not negative
        let witness = CommitmentWitness::new(amount.into(), Scalar::random(rng));
        let amount_enc_blinding = witness.blinding();

        let non_neg_amount_proof = InRangeProof::from(prove_within_range(
            amount.into(),
            amount_enc_blinding,
            BALANCE_RANGE,
            rng,
        )?);

        // Prove that the amount encrypted under different public keys are the same
        let (sndr_new_enc_amount, rcvr_new_enc_amount) =
            encrypt_using_two_pub_keys(&witness, sndr_enc_keys.pblc, rcvr_pub_key);

        let amount_equal_cipher_proof =
            CipherEqualDifferentPubKeyProof::from(single_property_prover(
                EncryptingSameValueProverAwaitingChallenge {
                    pub_key1: sndr_enc_keys.pblc,
                    pub_key2: rcvr_pub_key,
                    w: Zeroizing::new(witness.clone()),
                    pc_gens: &gens,
                },
                rng,
            )?);

        // Refresh the encrypted balance and prove that the refreshment was done
        // correctly
        let balance_refresh_enc_blinding = Scalar::random(rng);
        let refreshed_enc_balance = sndr_pub_account
            .enc_balance
            .cipher
            .refresh(&sndr_enc_keys.scrt, balance_refresh_enc_blinding)?;
        let balance_refreshed_same_proof =
            CipherEqualSamePubKeyProof::from(single_property_prover(
                CipherTextRefreshmentProverAwaitingChallenge::new(
                    sndr_enc_keys.scrt.clone(),
                    sndr_pub_account.enc_balance.cipher,
                    refreshed_enc_balance,
                    &gens,
                ),
                rng,
            )?);

        // Prove that the sender has enough funds
        let blinding = balance_refresh_enc_blinding - amount_enc_blinding;
        let enough_fund_proof = InRangeProof::from(prove_within_range(
            (balance - amount).into(),
            blinding,
            BALANCE_RANGE,
            rng,
        )?);

        // Refresh the encrypted asset id of the sender account and prove that the
        // refreshment was done correctly
        let asset_id_refresh_enc_blinding = Scalar::random(rng);
        let refreshed_enc_asset_id = sndr_pub_account.enc_asset_id.cipher.refresh_with_hint(
            &sndr_enc_keys.scrt,
            asset_id_refresh_enc_blinding,
            &asset_id.clone().into(),
        )?;

        let asset_id_refreshed_same_proof =
            CipherEqualSamePubKeyProof::from(single_property_prover(
                CipherTextRefreshmentProverAwaitingChallenge::new(
                    sndr_enc_keys.scrt.clone(),
                    sndr_pub_account.enc_asset_id.cipher,
                    refreshed_enc_asset_id,
                    &gens,
                ),
                rng,
            )?);

        // Prove the new refreshed encrytped asset id is the same as the one
        // encrypted by the receiver's pub key
        let asset_id_witness =
            CommitmentWitness::new(asset_id.into(), asset_id_refresh_enc_blinding);
        let enc_asset_id_using_rcvr = rcvr_pub_key.encrypt(&asset_id_witness);
        let asset_id_equal_cipher_with_sndr_rcvr_keys_proof =
            CipherEqualDifferentPubKeyProof::from(single_property_prover(
                EncryptingSameValueProverAwaitingChallenge {
                    pub_key1: sndr_enc_keys.pblc,
                    pub_key2: rcvr_pub_key,
                    w: Zeroizing::new(asset_id_witness),
                    pc_gens: &gens,
                },
                rng,
            )?);

        // Gather the content and sign it
        let content = PubInitConfidentialTxDataContent {
            amount_equal_cipher_proof,
            non_neg_amount_proof,
            enough_fund_proof,
            asset_id_equal_cipher_with_sndr_rcvr_keys_proof,
            balance_refreshed_same_proof,
            asset_id_refreshed_same_proof,
            memo: ConfidentialTxMemo {
                sndr_account_id: sndr_pub_account.id,
                rcvr_account_id: rcvr_pub_account.id,
                enc_amount_using_sndr: sndr_new_enc_amount.into(),
                enc_amount_using_rcvr: rcvr_new_enc_amount.into(),
                sndr_pub_key: sndr_enc_keys.pblc,
                rcvr_pub_key: rcvr_pub_key,
                refreshed_enc_balance: refreshed_enc_balance.into(),
                refreshed_enc_asset_id: refreshed_enc_asset_id.into(),
                enc_asset_id_using_rcvr: enc_asset_id_using_rcvr.into(),
            },
        };

        let message = content.to_bytes();
        let sig = sndr_sign_keys.sign(SIG_CTXT.bytes(&message));

        Ok((
            PubInitConfidentialTxData { content, sig },
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
        sndr_pub_account: &PubAccount,
        rcvr_account: Account,
        enc_asset_id: EncryptedAssetId,
        amount: Balance,
        state: ConfidentialTxState,
        rng: &mut StdRng,
    ) -> Fallible<(PubFinalConfidentialTxData, ConfidentialTxState)> {
        self.finalize_by_receiver(conf_tx_init_data, rcvr_account, state, amount, rng)?;

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
        rcvr_account: Account,
        state: ConfidentialTxState,
        expected_amount: Balance,
        rng: &mut StdRng,
    ) -> Fallible<(PubFinalConfidentialTxData, ConfidentialTxState)> {
        ensure!(
            state == ConfidentialTxState::InitilaziationJustification(TxSubstate::Validated),
            ErrorKind::InvalidPreviousState { state }
        );
        let rcvr_enc_sec = &rcvr_account.scrt.enc_keys.scrt;
        let rcvr_sign_keys = &rcvr_account.scrt.sign_keys;
        let rcvr_pub_account = &rcvr_account.pblc.content;

        // Check that the amount is correct
        let received_amount =
            rcvr_enc_sec.decrypt(&conf_tx_init_data.content.memo.enc_amount_using_rcvr.cipher)?;

        ensure!(
            received_amount == expected_amount,
            ErrorKind::TransactionAmountMismatch {
                expected_amount,
                received_amount
            }
        );

        // Check that the received public keys match
        let acc_key = conf_tx_init_data.content.memo.rcvr_pub_key;
        let memo_key = rcvr_pub_account.memo.owner_enc_pub_key;
        ensure!(acc_key == memo_key, ErrorKind::InputPubKeyMismatch);

        // Generate proof of equality of asset ids
        let enc_asset_id_from_sndr = conf_tx_init_data.content.memo.enc_asset_id_using_rcvr;
        let enc_asset_id_from_rcvr_acc = rcvr_pub_account.enc_asset_id;
        let gens = PedersenGens::default();
        let prover = CipherTextRefreshmentProverAwaitingChallenge::new(
            rcvr_enc_sec.clone(),
            enc_asset_id_from_rcvr_acc.cipher,
            enc_asset_id_from_sndr.cipher,
            &gens,
        );

        let (init, response) = single_property_prover(prover, rng)?;

        // gather the content and sign it
        let content = PubFinalConfidentialTxDataContent {
            init_data: conf_tx_init_data,
            asset_id_from_sndr_equal_to_rcvr_proof: CipherEqualSamePubKeyProof { init, response },
        };

        let message = content.to_bytes();
        let sig = rcvr_sign_keys.sign(SIG_CTXT.bytes(&message));

        Ok((
            PubFinalConfidentialTxData { content, sig },
            ConfidentialTxState::Finalization(TxSubstate::Started),
        ))
    }
}

// ------------------------------------------------------------------------------------------------
// -                                          Validator                                           -
// ------------------------------------------------------------------------------------------------

fn verify_initital_transaction_proofs(
    transaction: &PubInitConfidentialTxData,
    sndr_account: &PubAccount,
) -> Fallible<()> {
    let memo = &transaction.content.memo;
    let init_data = &transaction.content;
    let sndr_account = &sndr_account.content;
    let gens = &PedersenGens::default();

    ensure!(
        sndr_account.id == memo.sndr_account_id,
        ErrorKind::AccountIdMismatch
    );

    // Verify that the encrypted amounts are equal
    single_property_verifier(
        &EncryptingSameValueVerifier {
            pub_key1: memo.sndr_pub_key,
            pub_key2: memo.rcvr_pub_key,
            cipher1: memo.enc_amount_using_sndr.cipher,
            cipher2: memo.enc_amount_using_rcvr.cipher,
            pc_gens: &gens,
        },
        init_data.amount_equal_cipher_proof.init,
        init_data.amount_equal_cipher_proof.response,
    )?;

    let mut rng = OsRng::default();

    // Verify that the amount is not negative
    verify_within_range(
        init_data.non_neg_amount_proof.init.clone(),
        init_data.non_neg_amount_proof.response.clone(),
        init_data.non_neg_amount_proof.range,
        &mut rng,
    )?;

    // verify that the balance refreshment was done correctly
    single_property_verifier(
        &CipherTextRefreshmentVerifier::new(
            memo.sndr_pub_key,
            sndr_account.enc_balance.cipher,
            memo.refreshed_enc_balance.cipher,
            &gens,
        ),
        init_data.balance_refreshed_same_proof.init,
        init_data.balance_refreshed_same_proof.response,
    )?;

    // Verify that the balance has enough fund
    verify_within_range(
        init_data.enough_fund_proof.init.clone(),
        init_data.enough_fund_proof.response.clone(),
        init_data.enough_fund_proof.range,
        &mut rng,
    )?;

    // Verify that the asset id refreshment was done correctly
    single_property_verifier(
        &CipherTextRefreshmentVerifier::new(
            memo.sndr_pub_key,
            sndr_account.enc_asset_id.cipher,
            memo.refreshed_enc_asset_id.cipher,
            &gens,
        ),
        init_data.asset_id_refreshed_same_proof.init,
        init_data.asset_id_refreshed_same_proof.response,
    )?;

    // In the inital transaction, the sender has encrypted the asset id
    // using the receiver pub key. We verify that this encrypted asset id
    // is the same as the one in the sender account.
    single_property_verifier(
        &EncryptingSameValueVerifier {
            pub_key1: memo.sndr_pub_key,
            pub_key2: memo.rcvr_pub_key,
            cipher1: memo.refreshed_enc_asset_id.cipher,
            cipher2: memo.enc_asset_id_using_rcvr.cipher,
            pc_gens: &gens,
        },
        init_data
            .asset_id_equal_cipher_with_sndr_rcvr_keys_proof
            .init,
        init_data
            .asset_id_equal_cipher_with_sndr_rcvr_keys_proof
            .response,
    )?;

    Ok(())
}

/// Verifies the initial transaction.
pub struct CtxSenderValidator {}

impl ConfidentialTransactionInitVerifier for CtxSenderValidator {
    fn verify(
        &self,
        transaction: &PubInitConfidentialTxData,
        sndr_account: &PubAccount,
        state: ConfidentialTxState,
    ) -> Fallible<ConfidentialTxState> {
        ensure!(
            state == ConfidentialTxState::Initialization(TxSubstate::Started),
            ErrorKind::InvalidPreviousState { state }
        );

        let message = transaction.content.to_bytes();
        let _ = sndr_account
            .content
            .memo
            .owner_sign_pub_key
            .verify(SIG_CTXT.bytes(&message), &transaction.sig)?;

        verify_initital_transaction_proofs(transaction, sndr_account)?;

        Ok(ConfidentialTxState::Initialization(TxSubstate::Validated))
    }
}

/// Verifies the proofs that are performed by both the Sender and the Receiver of a
/// confidential transaction.
pub struct CtxReceiverValidator {}

impl CtxReceiverValidator {
    pub fn verify_finalize_by_receiver(
        &self,
        sndr_account: &PubAccount,
        rcvr_account: &PubAccount,
        conf_tx_final_data: &PubFinalConfidentialTxData,
        state: ConfidentialTxState,
    ) -> Fallible<()> {
        ensure!(
            state == ConfidentialTxState::Finalization(TxSubstate::Started),
            ErrorKind::InvalidPreviousState { state }
        );

        let message = conf_tx_final_data.content.to_bytes();
        let _ = rcvr_account
            .content
            .memo
            .owner_sign_pub_key
            .verify(SIG_CTXT.bytes(&message), &conf_tx_final_data.sig)?;

        let memo = &conf_tx_final_data.content.init_data.content.memo;
        let init_data = &conf_tx_final_data.content.init_data;
        let final_content = &conf_tx_final_data.content;

        verify_initital_transaction_proofs(init_data, &sndr_account)?;

        // In the inital transaction, the sender has encrypted the asset id
        // using the receiver pub key. We verify that this encrypted asset id
        // is the same as the one in the receiver account
        single_property_verifier(
            &CipherTextRefreshmentVerifier::new(
                memo.rcvr_pub_key,
                rcvr_account.content.enc_asset_id.cipher,
                memo.enc_asset_id_using_rcvr.cipher,
                &PedersenGens::default(),
            ),
            final_content.asset_id_from_sndr_equal_to_rcvr_proof.init,
            final_content
                .asset_id_from_sndr_equal_to_rcvr_proof
                .response,
        )?;

        Ok(())
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
        asset_proofs::ElgamalSecretKey,
        mercat::{
            AccountMemo, ConfidentialTxMemo, CorrectnessProof, EncryptedAmount, EncryptionKeys,
            EncryptionPubKey, MembershipProof, PubAccountContent, SecAccount, Signature,
            SigningKeys, SigningPubKey, WellformednessProof,
        },
        AssetId,
    };
    use curve25519_dalek::scalar::Scalar;
    use rand::SeedableRng;
    use rand_core::{CryptoRng, RngCore};
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

    fn mock_gen_sign_key_pair(seed: u8) -> SigningKeys {
        let mut rng = StdRng::from_seed([seed; 32]);
        schnorrkel::Keypair::generate_with(&mut rng)
    }

    fn mock_ctx_init_memo<R: RngCore + CryptoRng>(
        rcvr_pub_key: EncryptionPubKey,
        amount: Balance,
        asset_id: AssetId,
        rng: &mut R,
    ) -> ConfidentialTxMemo {
        let (_, enc_amount_using_rcvr) = rcvr_pub_key.key.encrypt_value(amount.into(), rng);
        let (_, enc_asset_id_using_rcvr) = rcvr_pub_key.key.encrypt_value(asset_id.into(), rng);
        ConfidentialTxMemo {
            sndr_account_id: 0,
            rcvr_account_id: 0,
            enc_amount_using_sndr: EncryptedAmount::default(),
            enc_amount_using_rcvr: EncryptedAmount::from(enc_amount_using_rcvr),
            sndr_pub_key: EncryptionPubKey::default(),
            rcvr_pub_key,
            refreshed_enc_balance: EncryptedAmount::default(),
            refreshed_enc_asset_id: EncryptedAssetId::default(),
            enc_asset_id_using_rcvr: EncryptedAssetId::from(enc_asset_id_using_rcvr),
        }
    }

    fn mock_gen_account<R: RngCore + CryptoRng>(
        rcvr_enc_pub_key: EncryptionPubKey,
        rcvr_sign_pub_key: SigningPubKey,
        asset_id: AssetId,
        balance: Balance,
        rng: &mut R,
    ) -> Fallible<PubAccount> {
        let (_, enc_asset_id) = rcvr_enc_pub_key.key.encrypt_value(asset_id.into(), rng);
        let (_, enc_balance) = rcvr_enc_pub_key
            .key
            .encrypt_value(Scalar::from(balance), rng);

        Ok(PubAccount {
            content: PubAccountContent {
                id: 1,
                enc_asset_id: enc_asset_id.into(),
                enc_balance: enc_balance.into(),
                asset_wellformedness_proof: WellformednessProof::default(),
                asset_membership_proof: MembershipProof::default(),
                balance_correctness_proof: CorrectnessProof::default(),
                memo: AccountMemo::new(rcvr_enc_pub_key, rcvr_sign_pub_key),
            },
            sig: Signature::from_bytes(&[128u8; 64]).expect("Invalid Schnorrkel signature"),
        })
    }

    fn mock_ctx_init_data<R: RngCore + CryptoRng>(
        rcvr_pub_key: EncryptionPubKey,
        expected_amount: Balance,
        asset_id: AssetId,
        sig: Signature,
        rng: &mut R,
    ) -> PubInitConfidentialTxData {
        PubInitConfidentialTxData {
            content: PubInitConfidentialTxDataContent {
                memo: mock_ctx_init_memo(rcvr_pub_key, expected_amount, asset_id, rng),
                asset_id_equal_cipher_with_sndr_rcvr_keys_proof:
                    CipherEqualDifferentPubKeyProof::default(),
                amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof::default(),
                non_neg_amount_proof: InRangeProof::default(),
                enough_fund_proof: InRangeProof::default(),
                balance_refreshed_same_proof: CipherEqualSamePubKeyProof::default(),
                asset_id_refreshed_same_proof: CipherEqualSamePubKeyProof::default(),
            },
            sig,
        }
    }

    // -------------------------- tests -----------------------

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_success() {
        let ctx_rcvr = CtxReceiver {};
        let expected_amount = 10;
        let asset_id = AssetId::from(20u32);
        let balance = 0;
        let mut rng = StdRng::from_seed([17u8; 32]);

        let rcvr_enc_keys = mock_gen_enc_key_pair(17u8);
        let rcvr_sign_keys = mock_gen_sign_key_pair(18u8);

        let sign = rcvr_sign_keys.sign(SIG_CTXT.bytes(b""));

        let ctx_init_data = mock_ctx_init_data(
            rcvr_enc_keys.pblc,
            expected_amount,
            asset_id.clone(),
            sign,
            &mut rng,
        );
        let rcvr_account = Account {
            pblc: mock_gen_account(
                rcvr_enc_keys.pblc,
                rcvr_sign_keys.public,
                asset_id.clone(),
                balance,
                &mut rng,
            )
            .unwrap(),
            scrt: SecAccount {
                enc_keys: rcvr_enc_keys,
                sign_keys: rcvr_sign_keys,
                asset_id: asset_id.clone(),
                asset_id_witness: CommitmentWitness::from((asset_id.into(), &mut rng)),
            },
        };
        let valid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Validated);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_account,
            valid_state,
            expected_amount,
            &mut rng,
        );

        result.unwrap();
        // Correctness of the proof will be verified in the verify function
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_prev_state_error() {
        let ctx_rcvr = CtxReceiver {};
        let expected_amount = 10;
        let asset_id = AssetId::from(20u32);
        let balance = 0;
        let mut rng = StdRng::from_seed([17u8; 32]);

        let rcvr_enc_keys = mock_gen_enc_key_pair(17u8);
        let rcvr_sign_keys = mock_gen_sign_key_pair(18u8);
        let sign = rcvr_sign_keys.sign(SIG_CTXT.bytes(b""));

        let ctx_init_data = mock_ctx_init_data(
            rcvr_enc_keys.pblc,
            expected_amount,
            asset_id.clone(),
            sign,
            &mut rng,
        );
        let rcvr_account = Account {
            pblc: mock_gen_account(
                rcvr_enc_keys.pblc,
                rcvr_sign_keys.public,
                asset_id.clone(),
                balance,
                &mut rng,
            )
            .unwrap(),
            scrt: SecAccount {
                enc_keys: rcvr_enc_keys,
                sign_keys: rcvr_sign_keys,
                asset_id: asset_id.clone(),
                asset_id_witness: CommitmentWitness::from((asset_id.into(), &mut rng)),
            },
        };
        let invalid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Started);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_account,
            invalid_state,
            expected_amount,
            &mut rng,
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
        let asset_id = AssetId::from(20);
        let balance = 0;
        let mut rng = StdRng::from_seed([17u8; 32]);

        let rcvr_enc_keys = mock_gen_enc_key_pair(17u8);
        let rcvr_sign_keys = mock_gen_sign_key_pair(18u8);
        let sign = rcvr_sign_keys.sign(SIG_CTXT.bytes(b""));

        let ctx_init_data = mock_ctx_init_data(
            rcvr_enc_keys.pblc,
            received_amount,
            asset_id.clone(),
            sign,
            &mut rng,
        );
        let rcvr_account = Account {
            pblc: mock_gen_account(
                rcvr_enc_keys.pblc,
                rcvr_sign_keys.public,
                asset_id.clone(),
                balance,
                &mut rng,
            )
            .unwrap(),
            scrt: SecAccount {
                enc_keys: rcvr_enc_keys,
                sign_keys: rcvr_sign_keys,
                asset_id: asset_id.clone(),
                asset_id_witness: CommitmentWitness::from((asset_id.into(), &mut rng)),
            },
        };
        let valid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Validated);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_account,
            valid_state,
            expected_amount,
            &mut rng,
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
        let asset_id = AssetId::from(20);
        let balance = 0;
        let mut rng = StdRng::from_seed([17u8; 32]);

        let rcvr_enc_keys = mock_gen_enc_key_pair(17u8);
        let wrong_enc_keys = mock_gen_enc_key_pair(18u8);
        let rcvr_sign_keys = mock_gen_sign_key_pair(18u8);
        let sign = rcvr_sign_keys.sign(SIG_CTXT.bytes(b""));

        let ctx_init_data = mock_ctx_init_data(
            rcvr_enc_keys.pblc,
            expected_amount,
            asset_id.clone(),
            sign,
            &mut rng,
        );
        let rcvr_account = Account {
            pblc: mock_gen_account(
                wrong_enc_keys.pblc,
                rcvr_sign_keys.public,
                asset_id.clone(),
                balance,
                &mut rng,
            )
            .unwrap(),
            scrt: SecAccount {
                enc_keys: rcvr_enc_keys,
                sign_keys: rcvr_sign_keys,
                asset_id: asset_id.clone(),
                asset_id_witness: CommitmentWitness::from((asset_id.into(), &mut rng)),
            },
        };
        let valid_state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Validated);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_account,
            valid_state,
            expected_amount,
            &mut rng,
        );

        assert_err!(result, ErrorKind::InputPubKeyMismatch);
    }

    // ------------------------------ Test simple scenarios

    #[test]
    #[wasm_bindgen_test]
    fn test_ctx_create_finalize_validate_success() {
        let sndr = CtxSender {};
        let rcvr = CtxReceiver {};
        let sndr_vldtr = CtxSenderValidator {};
        let rcvr_vldtr = CtxReceiverValidator {};
        let asset_id = AssetId::from(20);
        let sndr_balance = 40;
        let rcvr_balance = 0;
        let amount = 30;

        let mut rng = StdRng::from_seed([17u8; 32]);

        let sndr_enc_keys = mock_gen_enc_key_pair(10u8);
        let sndr_sign_keys = mock_gen_sign_key_pair(11u8);

        let rcvr_enc_keys = mock_gen_enc_key_pair(12u8);
        let rcvr_sign_keys = mock_gen_sign_key_pair(13u8);

        let rcvr_account = Account {
            pblc: mock_gen_account(
                rcvr_enc_keys.pblc,
                rcvr_sign_keys.public.clone(),
                asset_id.clone(),
                rcvr_balance,
                &mut rng,
            )
            .unwrap(),
            scrt: SecAccount {
                enc_keys: rcvr_enc_keys,
                sign_keys: rcvr_sign_keys,
                asset_id: asset_id.clone(),
                asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
            },
        };

        let sndr_account = Account {
            pblc: mock_gen_account(
                sndr_enc_keys.pblc,
                sndr_sign_keys.public.clone(),
                asset_id.clone(),
                sndr_balance,
                &mut rng,
            )
            .unwrap(),
            scrt: SecAccount {
                enc_keys: sndr_enc_keys,
                sign_keys: sndr_sign_keys,
                asset_id: asset_id.clone(),
                asset_id_witness: CommitmentWitness::from((asset_id.into(), &mut rng)),
            },
        };

        // Create the trasaction and check its result and state
        let result = sndr.create(&sndr_account, &rcvr_account.pblc, amount, &mut rng);
        let (ctx_init_data, state) = result.unwrap();
        assert_eq!(
            state,
            ConfidentialTxState::Initialization(TxSubstate::Started)
        );

        // Verify the initialization step
        let result = sndr_vldtr.verify(&ctx_init_data, &sndr_account.pblc, state);
        let state = result.unwrap();
        assert_eq!(
            state,
            ConfidentialTxState::Initialization(TxSubstate::Validated)
        );

        // TODO: skipping the mediator step. Therefore assuming that it has passed.
        let state = ConfidentialTxState::InitilaziationJustification(TxSubstate::Validated);

        // Finalize the transaction and check its state
        let result =
            rcvr.finalize_by_receiver(ctx_init_data, rcvr_account.clone(), state, amount, &mut rng);
        let (ctx_finalized_data, finalized_state) = result.unwrap();
        assert_eq!(
            finalized_state,
            ConfidentialTxState::Finalization(TxSubstate::Started)
        );

        // verify the finalization step
        let result = rcvr_vldtr.verify_finalize_by_receiver(
            &sndr_account.pblc,
            &rcvr_account.pblc,
            &ctx_finalized_data,
            finalized_state,
        );
        result.unwrap();
    }

    // TODO other test cases
    // 1. balance less than amount
}
