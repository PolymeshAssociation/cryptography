use crate::{
    asset_proofs::{
        ciphertext_refreshment_proof::CipherTextRefreshmentProverAwaitingChallenge,
        ciphertext_refreshment_proof::CipherTextRefreshmentVerifier,
        correctness_proof::{CorrectnessProverAwaitingChallenge, CorrectnessVerifier},
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
        ConfidentialTransactionFinalizationVerifier, ConfidentialTransactionInitVerifier,
        ConfidentialTransactionMediator, ConfidentialTransactionMediatorVerifier,
        ConfidentialTransactionReceiver, ConfidentialTransactionSender, ConfidentialTxMemo,
        ConfidentialTxState, CorrectnessProof, EncryptedAssetId, EncryptionKeys, EncryptionPubKey,
        InRangeProof, JustifiedPubFinalConfidentialTxData, PubAccount, PubFinalConfidentialTxData,
        PubFinalConfidentialTxDataContent, PubInitConfidentialTxData,
        PubInitConfidentialTxDataContent, SigningKeys, SigningPubKey, TxSubstate,
    },
    AssetId, Balance, BALANCE_RANGE,
};

use bulletproofs::PedersenGens;
use codec::Encode;
use curve25519_dalek::scalar::Scalar;
use lazy_static::lazy_static;
use rand_core::{CryptoRng, RngCore};
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
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct CtxSender {}

impl ConfidentialTransactionSender for CtxSender {
    fn create_transaction<T: RngCore + CryptoRng>(
        &self,
        sndr_account: &Account,
        rcvr_pub_account: &PubAccount,
        mdtr_pub_key: &EncryptionPubKey,
        amount: Balance,
        rng: &mut T,
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
            CommitmentWitness::new(asset_id.clone().into(), asset_id_refresh_enc_blinding);
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

        // Prepare the correctness proofs for the mediator
        let asset_id_witness_blinding_for_mdtr = Scalar::random(rng);
        let asset_id_witness_for_mdtr =
            CommitmentWitness::new(asset_id.into(), asset_id_witness_blinding_for_mdtr);
        let enc_asset_id_for_mdtr = mdtr_pub_key.encrypt(&asset_id_witness_for_mdtr);

        let amount_witness_blinding_for_mdtr = Scalar::random(rng);
        let amount_witness_for_mdtr =
            CommitmentWitness::new(amount.into(), amount_witness_blinding_for_mdtr);
        let enc_amount_for_mdtr = mdtr_pub_key.encrypt(&amount_witness_for_mdtr);

        let asset_id_correctness_proof = CorrectnessProof::from(single_property_prover(
            CorrectnessProverAwaitingChallenge {
                pub_key: mdtr_pub_key.clone(),
                w: asset_id_witness_for_mdtr,
                pc_gens: &gens,
            },
            rng,
        )?);

        let amount_correctness_proof = CorrectnessProof::from(single_property_prover(
            CorrectnessProverAwaitingChallenge {
                pub_key: mdtr_pub_key.clone(),
                w: amount_witness_for_mdtr,
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
            asset_id_correctness_proof,
            amount_correctness_proof,
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
                enc_asset_id_for_mdtr: enc_asset_id_for_mdtr.into(),
                enc_amount_for_mdtr: enc_amount_for_mdtr.into(),
            },
        };

        let message = content.encode();
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
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct CtxReceiver {}

impl ConfidentialTransactionReceiver for CtxReceiver {
    fn finalize_and_process<T: RngCore + CryptoRng>(
        &self,
        conf_tx_init_data: PubInitConfidentialTxData,
        _sndr_pub_account: &PubAccount,
        rcvr_account: Account,
        _enc_asset_id: EncryptedAssetId,
        amount: Balance,
        state: ConfidentialTxState,
        rng: &mut T,
    ) -> Fallible<(PubFinalConfidentialTxData, ConfidentialTxState)> {
        self.finalize_by_receiver(conf_tx_init_data, rcvr_account, state, amount, rng)?;

        // TODO: CRYP-110 also ensure that _sndr_pub_account and _enc_asset_id are actually used
        Err(ErrorKind::NotImplemented.into())
    }
}

impl CtxReceiver {
    /// This function is called by the receiver of the transaction to finalize the
    /// transaction. It corresponds to `FinalizeCTX` function of the MERCAT paper.
    pub fn finalize_by_receiver<T: RngCore + CryptoRng>(
        &self,
        conf_tx_init_data: PubInitConfidentialTxData,
        rcvr_account: Account,
        state: ConfidentialTxState,
        expected_amount: Balance,
        rng: &mut T,
    ) -> Fallible<(PubFinalConfidentialTxData, ConfidentialTxState)> {
        ensure!(
            state == ConfidentialTxState::Initialization(TxSubstate::Validated),
            ErrorKind::InvalidPreviousState { state }
        );
        let rcvr_enc_sec = &rcvr_account.scrt.enc_keys.scrt;
        let rcvr_sign_keys = &rcvr_account.scrt.sign_keys;
        let rcvr_pub_account = &rcvr_account.pblc.content;

        // Check that the amount is correct
        rcvr_enc_sec
            .verify(
                &conf_tx_init_data.content.memo.enc_amount_using_rcvr.cipher,
                &expected_amount.into(),
            )
            .map_err(|_| ErrorKind::TransactionAmountMismatch { expected_amount })?;

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

        let message = content.encode();
        let sig = rcvr_sign_keys.sign(SIG_CTXT.bytes(&message));

        Ok((
            PubFinalConfidentialTxData { content, sig },
            ConfidentialTxState::Finalization(TxSubstate::Started),
        ))
    }
}

// ------------------------------------------------------------------------------------------------
// -                                           Mediator                                           -
// ------------------------------------------------------------------------------------------------
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct CtxMediator {}

impl ConfidentialTransactionMediator for CtxMediator {
    fn justify(
        &self,
        conf_tx_final_data: PubFinalConfidentialTxData,
        state: ConfidentialTxState,
        mdtr_enc_keys: &EncryptionKeys,
        mdtr_sign_keys: &SigningKeys,
        asset_id_hint: AssetId,
    ) -> Fallible<(JustifiedPubFinalConfidentialTxData, ConfidentialTxState)> {
        // TODO: may need to change the signature CRYP-111
        ensure!(
            state == ConfidentialTxState::Finalization(TxSubstate::Validated),
            ErrorKind::InvalidPreviousState { state }
        );

        let gens = &PedersenGens::default();
        let tx_data = &conf_tx_final_data.content.init_data.content;

        // Verify that the encrypted amount is correct
        let amount = mdtr_enc_keys
            .scrt
            .decrypt(&tx_data.memo.enc_amount_for_mdtr.cipher)?;
        single_property_verifier(
            &CorrectnessVerifier {
                value: amount.into(),
                pub_key: mdtr_enc_keys.pblc,
                cipher: tx_data.memo.enc_amount_for_mdtr.cipher,
                pc_gens: &gens,
            },
            tx_data.amount_correctness_proof.init,
            tx_data.amount_correctness_proof.response,
        )?;

        // Verify that the encrypted asset_id is correct
        mdtr_enc_keys.scrt.verify(
            &tx_data.memo.enc_asset_id_for_mdtr.cipher,
            &asset_id_hint.clone().into(),
        )?;

        let asset_id = asset_id_hint;
        single_property_verifier(
            &CorrectnessVerifier {
                value: asset_id.into(),
                pub_key: mdtr_enc_keys.pblc,
                cipher: tx_data.memo.enc_asset_id_for_mdtr.cipher,
                pc_gens: &gens,
            },
            tx_data.asset_id_correctness_proof.init,
            tx_data.asset_id_correctness_proof.response,
        )?;

        let message = conf_tx_final_data.encode();
        let sig = mdtr_sign_keys.sign(SIG_CTXT.bytes(&message));

        Ok((
            JustifiedPubFinalConfidentialTxData {
                conf_tx_final_data,
                sig,
            },
            ConfidentialTxState::FinalizationJustification(TxSubstate::Started),
        ))
    }
}

// ------------------------------------------------------------------------------------------------
// -                                          Validator                                           -
// ------------------------------------------------------------------------------------------------

/// Verifies the initial transaction.
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct CtxSenderValidator {}

/// Verifies the proofs that are performed by both the Sender and the Receiver of a
/// confidential transaction.
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct CtxReceiverValidator {}

/// Verifies the signature and the state of the justification phase of a
/// confidential transaction.
pub struct CtxMediatorValidator {}

fn verify_initital_transaction_proofs<R: RngCore + CryptoRng>(
    transaction: &PubInitConfidentialTxData,
    sndr_account: &PubAccount,
    rng: &mut R,
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

    // Verify that the amount is not negative
    verify_within_range(
        init_data.non_neg_amount_proof.init.clone(),
        init_data.non_neg_amount_proof.response.clone(),
        init_data.non_neg_amount_proof.range,
        rng,
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
        rng,
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

impl ConfidentialTransactionInitVerifier for CtxSenderValidator {
    fn verify<R: RngCore + CryptoRng>(
        &self,
        transaction: &PubInitConfidentialTxData,
        sndr_account: &PubAccount,
        state: ConfidentialTxState,
        rng: &mut R,
    ) -> Fallible<ConfidentialTxState> {
        ensure!(
            state == ConfidentialTxState::Initialization(TxSubstate::Started),
            ErrorKind::InvalidPreviousState { state }
        );

        let message = transaction.content.encode();
        let _ = sndr_account
            .content
            .memo
            .owner_sign_pub_key
            .verify(SIG_CTXT.bytes(&message), &transaction.sig)?;

        verify_initital_transaction_proofs(transaction, sndr_account, rng)?;

        Ok(ConfidentialTxState::Initialization(TxSubstate::Validated))
    }
}

impl ConfidentialTransactionFinalizationVerifier for CtxReceiverValidator {
    fn verify_finalize_by_receiver<R: RngCore + CryptoRng>(
        &self,
        sndr_account: &PubAccount,
        rcvr_account: &PubAccount,
        conf_tx_final_data: &PubFinalConfidentialTxData,
        state: ConfidentialTxState,
        rng: &mut R,
    ) -> Fallible<ConfidentialTxState> {
        ensure!(
            state == ConfidentialTxState::Finalization(TxSubstate::Started),
            ErrorKind::InvalidPreviousState { state }
        );

        let message = conf_tx_final_data.content.encode();
        let _ = rcvr_account
            .content
            .memo
            .owner_sign_pub_key
            .verify(SIG_CTXT.bytes(&message), &conf_tx_final_data.sig)?;

        let memo = &conf_tx_final_data.content.init_data.content.memo;
        let init_data = &conf_tx_final_data.content.init_data;
        let final_content = &conf_tx_final_data.content;

        verify_initital_transaction_proofs(init_data, &sndr_account, rng)?;

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

        Ok(ConfidentialTxState::Finalization(TxSubstate::Validated))
    }
}

impl ConfidentialTransactionMediatorVerifier for CtxMediatorValidator {
    fn verify(
        &self,
        conf_tx_justified_final_data: &JustifiedPubFinalConfidentialTxData,
        mdtr_sign_pub_key: &SigningPubKey,
        state: ConfidentialTxState,
    ) -> Fallible<ConfidentialTxState> {
        ensure!(
            state == ConfidentialTxState::FinalizationJustification(TxSubstate::Started),
            ErrorKind::InvalidPreviousState { state }
        );

        let ctx_data = &conf_tx_justified_final_data;
        let message = ctx_data.conf_tx_final_data.encode();
        let _ = mdtr_sign_pub_key.verify(SIG_CTXT.bytes(&message), &ctx_data.sig)?;

        Ok(ConfidentialTxState::FinalizationJustification(
            TxSubstate::Validated,
        ))
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
    use rand::rngs::StdRng;
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
        let (_, enc_amount_using_rcvr) = rcvr_pub_key.encrypt_value(amount.into(), rng);
        let (_, enc_asset_id_using_rcvr) = rcvr_pub_key.encrypt_value(asset_id.into(), rng);
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
            enc_amount_for_mdtr: EncryptedAmount::default(),
            enc_asset_id_for_mdtr: EncryptedAssetId::default(),
        }
    }

    fn mock_gen_account<R: RngCore + CryptoRng>(
        rcvr_enc_pub_key: EncryptionPubKey,
        rcvr_sign_pub_key: SigningPubKey,
        asset_id: AssetId,
        balance: Balance,
        rng: &mut R,
    ) -> Fallible<PubAccount> {
        let (_, enc_asset_id) = rcvr_enc_pub_key.encrypt_value(asset_id.into(), rng);
        let (_, enc_balance) = rcvr_enc_pub_key.encrypt_value(Scalar::from(balance), rng);

        Ok(PubAccount {
            content: PubAccountContent {
                id: 1,
                enc_asset_id: enc_asset_id.into(),
                enc_balance: enc_balance.into(),
                asset_wellformedness_proof: WellformednessProof::default(),
                asset_membership_proof: MembershipProof::default(),
                initial_balance_correctness_proof: CorrectnessProof::default(),
                memo: AccountMemo::new(rcvr_enc_pub_key, rcvr_sign_pub_key),
            },
            initial_sig: Signature::from_bytes(&[128u8; 64]).expect("Invalid Schnorrkel signature"),
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
                non_neg_amount_proof: InRangeProof::build(rng),
                enough_fund_proof: InRangeProof::build(rng),
                balance_refreshed_same_proof: CipherEqualSamePubKeyProof::default(),
                asset_id_refreshed_same_proof: CipherEqualSamePubKeyProof::default(),
                amount_correctness_proof: CorrectnessProof::default(),
                asset_id_correctness_proof: CorrectnessProof::default(),
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
        let valid_state = ConfidentialTxState::Initialization(TxSubstate::Validated);

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
        let invalid_state = ConfidentialTxState::Initialization(TxSubstate::Started);

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
        let valid_state = ConfidentialTxState::Initialization(TxSubstate::Validated);

        let result = ctx_rcvr.finalize_by_receiver(
            ctx_init_data,
            rcvr_account,
            valid_state,
            expected_amount,
            &mut rng,
        );

        assert_err!(
            result,
            ErrorKind::TransactionAmountMismatch { expected_amount }
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
        let valid_state = ConfidentialTxState::Initialization(TxSubstate::Validated);

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
        let mdtr = CtxMediator {};
        let sndr_vldtr = CtxSenderValidator {};
        let rcvr_vldtr = CtxReceiverValidator {};
        let mdtr_vldtr = CtxMediatorValidator {};
        let asset_id = AssetId::from(20);
        let sndr_balance = 40;
        let rcvr_balance = 0;
        let amount = 30;

        let mut rng = StdRng::from_seed([17u8; 32]);

        let sndr_enc_keys = mock_gen_enc_key_pair(10u8);
        let sndr_sign_keys = mock_gen_sign_key_pair(11u8);

        let rcvr_enc_keys = mock_gen_enc_key_pair(12u8);
        let rcvr_sign_keys = mock_gen_sign_key_pair(13u8);

        let mdtr_enc_keys = mock_gen_enc_key_pair(14u8);
        let mdtr_sign_keys = mock_gen_sign_key_pair(15u8);

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
                asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
            },
        };

        // Create the trasaction and check its result and state
        let result = sndr.create_transaction(
            &sndr_account,
            &rcvr_account.pblc,
            &mdtr_enc_keys.pblc,
            amount,
            &mut rng,
        );
        let (ctx_init_data, state) = result.unwrap();
        assert_eq!(
            state,
            ConfidentialTxState::Initialization(TxSubstate::Started)
        );

        // Verify the initialization step
        let result = sndr_vldtr.verify(&ctx_init_data, &sndr_account.pblc, state, &mut rng);
        let state = result.unwrap();
        assert_eq!(
            state,
            ConfidentialTxState::Initialization(TxSubstate::Validated)
        );

        // Finalize the transaction and check its state
        let result =
            rcvr.finalize_by_receiver(ctx_init_data, rcvr_account.clone(), state, amount, &mut rng);
        let (ctx_finalized_data, state) = result.unwrap();
        assert_eq!(
            state,
            ConfidentialTxState::Finalization(TxSubstate::Started)
        );

        // verify the finalization step
        let result = rcvr_vldtr.verify_finalize_by_receiver(
            &sndr_account.pblc,
            &rcvr_account.pblc,
            &ctx_finalized_data,
            state,
            &mut rng,
        );
        let state = result.unwrap();
        assert_eq!(
            state,
            ConfidentialTxState::Finalization(TxSubstate::Validated)
        );

        // justify the transaction
        let result = mdtr.justify(
            ctx_finalized_data,
            state,
            &mdtr_enc_keys,
            &mdtr_sign_keys,
            asset_id,
        );
        let (justified_finalized_ctx_data, state) = result.unwrap();
        assert_eq!(
            state,
            ConfidentialTxState::FinalizationJustification(TxSubstate::Started)
        );

        let result =
            mdtr_vldtr.verify(&justified_finalized_ctx_data, &mdtr_sign_keys.public, state);
        let state = result.unwrap();
        assert_eq!(
            state,
            ConfidentialTxState::FinalizationJustification(TxSubstate::Validated)
        );
    }
}
