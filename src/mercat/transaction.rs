use crate::{
    asset_proofs::{
        ciphertext_refreshment_proof::{
            CipherTextRefreshmentProverAwaitingChallenge, CipherTextRefreshmentVerifier,
        },
        correctness_proof::{
            CorrectnessProof, CorrectnessProverAwaitingChallenge, CorrectnessVerifier,
        },
        encrypt_using_two_pub_keys,
        encrypting_same_value_proof::{
            CipherEqualDifferentPubKeyProof, EncryptingSameValueProverAwaitingChallenge,
            EncryptingSameValueVerifier,
        },
        encryption_proofs::single_property_prover,
        encryption_proofs::single_property_verifier,
        range_proof::{prove_within_range, verify_within_range, InRangeProof},
        CommitmentWitness,
    },
    errors::{ErrorKind, Fallible},
    mercat::{
        Account, EncryptedAmount, EncryptionKeys, EncryptionPubKey, FinalizedTransferTx,
        FinalizedTransferTxContent, InitializedTransferTx, InitializedTransferTxContent,
        JustifiedTransferTx, OrderingState, PubAccount, SigningKeys, SigningPubKey,
        TransferTransactionMediator, TransferTransactionReceiver, TransferTransactionSender,
        TransferTransactionVerifier, TransferTxMemo, TxState, TxSubstate,
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
    static ref SIG_CTXT: SigningContext = signing_context(b"mercat/transaction");
}

// -------------------------------------------------------------------------------------
// -                                    Sender                                         -
// -------------------------------------------------------------------------------------

/// The sender of a confidential transaction. Sender creates a transaction
/// and performs initial proofs.
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct CtxSender {}

impl TransferTransactionSender for CtxSender {
    fn create_transaction<T: RngCore + CryptoRng>(
        &self,
        tx_id: u32,
        sndr_account: &Account,
        rcvr_pub_account: &PubAccount,
        mdtr_pub_key: &EncryptionPubKey,
        pending_enc_balance: EncryptedAmount,
        amount: Balance,
        sndr_pending_tx_counter: i32,
        rng: &mut T,
    ) -> Fallible<InitializedTransferTx> {
        let gens = PedersenGens::default();
        // NOTE: If this decryption ends up being too slow, we can pass in the balance
        // as input.
        let sndr_enc_keys = &sndr_account.scrt.enc_keys;
        let sndr_sign_keys = &sndr_account.scrt.sign_keys;
        let asset_id = sndr_account.scrt.asset_id_witness.value();
        let sndr_pub_account = &sndr_account.pblc;
        let rcvr_pub_key = rcvr_pub_account.memo.owner_enc_pub_key;

        let balance = sndr_enc_keys.scrt.decrypt(&pending_enc_balance)?;
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
        let refreshed_enc_balance =
            pending_enc_balance.refresh(&sndr_enc_keys.scrt, balance_refresh_enc_blinding)?;

        let balance_refreshed_same_proof = single_property_prover(
            CipherTextRefreshmentProverAwaitingChallenge::new(
                sndr_enc_keys.scrt.clone(),
                pending_enc_balance,
                refreshed_enc_balance,
                &gens,
            ),
            rng,
        )?;

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
        let refreshed_enc_asset_id = sndr_pub_account.enc_asset_id.refresh_with_hint(
            &sndr_enc_keys.scrt,
            asset_id_refresh_enc_blinding,
            &asset_id.clone().into(),
        )?;

        let asset_id_refreshed_same_proof = single_property_prover(
            CipherTextRefreshmentProverAwaitingChallenge::new(
                sndr_enc_keys.scrt.clone(),
                sndr_pub_account.enc_asset_id,
                refreshed_enc_asset_id,
                &gens,
            ),
            rng,
        )?;

        // Prove the new refreshed encrypted asset id is the same as the one
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
        let content = InitializedTransferTxContent {
            amount_equal_cipher_proof,
            non_neg_amount_proof,
            enough_fund_proof,
            asset_id_equal_cipher_with_sndr_rcvr_keys_proof,
            balance_refreshed_same_proof,
            asset_id_refreshed_same_proof,
            asset_id_correctness_proof,
            amount_correctness_proof,
            memo: TransferTxMemo {
                sndr_account_id: sndr_pub_account.id,
                rcvr_account_id: rcvr_pub_account.id,
                enc_amount_using_sndr: sndr_new_enc_amount.into(),
                enc_amount_using_rcvr: rcvr_new_enc_amount.into(),
                refreshed_enc_balance: refreshed_enc_balance.into(),
                refreshed_enc_asset_id: refreshed_enc_asset_id.into(),
                enc_asset_id_using_rcvr: enc_asset_id_using_rcvr.into(),
                enc_asset_id_for_mdtr: enc_asset_id_for_mdtr.into(),
                enc_amount_for_mdtr: enc_amount_for_mdtr.into(),
                sndr_ordering_state: OrderingState {
                    last_processed_tx_counter: sndr_pub_account.memo.last_processed_tx_counter,
                    last_pending_tx_counter: sndr_pending_tx_counter,
                    current_tx_id: tx_id,
                },
            },
        };

        let message = content.encode();
        let sig = sndr_sign_keys.sign(SIG_CTXT.bytes(&message));

        Ok(InitializedTransferTx { content, sig })
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

impl TransferTransactionReceiver for CtxReceiver {
    fn finalize_transaction<T: RngCore + CryptoRng>(
        &self,
        tx_id: u32,
        initialized_transaction: InitializedTransferTx,
        sndr_sign_pub_key: &SigningPubKey,
        rcvr_account: Account,
        amount: Balance,
        rcvr_pending_tx_counter: i32,
        rng: &mut T,
    ) -> Fallible<FinalizedTransferTx> {
        // Verify sender's signature.
        let ctx_data = &initialized_transaction;
        let message = ctx_data.content.encode();
        let _ = sndr_sign_pub_key.verify(SIG_CTXT.bytes(&message), &ctx_data.sig)?;

        self.finalize_by_receiver(
            tx_id,
            initialized_transaction,
            rcvr_account,
            amount,
            rcvr_pending_tx_counter,
            rng,
        )
    }
}

impl CtxReceiver {
    /// This function is called by the receiver of the transaction to finalize the
    /// transaction. It corresponds to `FinalizeCTX` function of the MERCAT paper.
    fn finalize_by_receiver<T: RngCore + CryptoRng>(
        &self,
        tx_id: u32,
        transaction_init_data: InitializedTransferTx,
        rcvr_account: Account,
        expected_amount: Balance,
        rcvr_pending_tx_counter: i32,
        rng: &mut T,
    ) -> Fallible<FinalizedTransferTx> {
        let rcvr_enc_sec = &rcvr_account.scrt.enc_keys.scrt;
        let rcvr_sign_keys = &rcvr_account.scrt.sign_keys;
        let rcvr_pub_account = &rcvr_account.pblc;

        // Check that the amount is correct
        rcvr_enc_sec
            .verify(
                &transaction_init_data.content.memo.enc_amount_using_rcvr,
                &expected_amount.into(),
            )
            .map_err(|_| ErrorKind::TransactionAmountMismatch { expected_amount })?;

        // Generate proof of equality of asset ids
        let enc_asset_id_from_sndr = transaction_init_data.content.memo.enc_asset_id_using_rcvr;
        let enc_asset_id_from_rcvr_acc = rcvr_pub_account.enc_asset_id;
        let gens = PedersenGens::default();
        let prover = CipherTextRefreshmentProverAwaitingChallenge::new(
            rcvr_enc_sec.clone(),
            enc_asset_id_from_rcvr_acc,
            enc_asset_id_from_sndr,
            &gens,
        );

        let proof = single_property_prover(prover, rng)?;

        // gather the content and sign it
        let content = FinalizedTransferTxContent {
            init_data: transaction_init_data,
            asset_id_from_sndr_equal_to_rcvr_proof: proof,
            rcvr_ordering_state: OrderingState {
                last_processed_tx_counter: rcvr_account.pblc.memo.last_processed_tx_counter,
                last_pending_tx_counter: rcvr_pending_tx_counter,
                current_tx_id: tx_id,
            },
        };

        let message = content.encode();
        let sig = rcvr_sign_keys.sign(SIG_CTXT.bytes(&message));

        Ok(FinalizedTransferTx { content, sig })
    }
}

// ------------------------------------------------------------------------------------------------
// -                                           Mediator                                           -
// ------------------------------------------------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct CtxMediator {}

impl TransferTransactionMediator for CtxMediator {
    fn justify_transaction(
        &self,
        finalized_transaction: FinalizedTransferTx,
        mdtr_enc_keys: &EncryptionKeys,
        mdtr_sign_keys: &SigningKeys,
        sndr_sign_pub_key: &SigningPubKey,
        rcvr_sign_pub_key: &SigningPubKey,
        asset_id_hint: AssetId,
    ) -> Fallible<JustifiedTransferTx> {
        // TODO: may need to change the signature CRYP-111

        // Verify receiver's signature on the transaction.
        let message = finalized_transaction.content.encode();
        let _ = rcvr_sign_pub_key.verify(SIG_CTXT.bytes(&message), &finalized_transaction.sig)?;

        // Verify sender's signature on the transaction.
        let init_tx_data = &finalized_transaction.content.init_data;
        let message = init_tx_data.content.encode();
        let _ = sndr_sign_pub_key.verify(SIG_CTXT.bytes(&message), &init_tx_data.sig)?;

        let gens = &PedersenGens::default();
        let tx_data = &finalized_transaction.content.init_data.content;

        // Verify that the encrypted amount is correct
        let amount = mdtr_enc_keys
            .scrt
            .decrypt(&tx_data.memo.enc_amount_for_mdtr)?;
        single_property_verifier(
            &CorrectnessVerifier {
                value: amount.into(),
                pub_key: mdtr_enc_keys.pblc,
                cipher: tx_data.memo.enc_amount_for_mdtr,
                pc_gens: &gens,
            },
            tx_data.amount_correctness_proof,
        )?;

        // Verify that the encrypted asset_id is correct
        mdtr_enc_keys.scrt.verify(
            &tx_data.memo.enc_asset_id_for_mdtr,
            &asset_id_hint.clone().into(),
        )?;

        let asset_id = asset_id_hint;
        single_property_verifier(
            &CorrectnessVerifier {
                value: asset_id.into(),
                pub_key: mdtr_enc_keys.pblc,
                cipher: tx_data.memo.enc_asset_id_for_mdtr,
                pc_gens: &gens,
            },
            tx_data.asset_id_correctness_proof,
        )?;

        let message = finalized_transaction.encode();
        let sig = mdtr_sign_keys.sign(SIG_CTXT.bytes(&message));

        Ok(JustifiedTransferTx {
            content: finalized_transaction,
            sig,
        })
    }
}

// ------------------------------------------------------------------------------------------------
// -                                          Validator                                           -
// ------------------------------------------------------------------------------------------------

/// Transaction Validator.
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct TransactionValidator {}

impl TransferTransactionVerifier for TransactionValidator {
    fn verify_transaction<R: RngCore + CryptoRng>(
        &self,
        justified_transaction: &JustifiedTransferTx,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        mdtr_sign_pub_key: &SigningPubKey,
        pending_balance: EncryptedAmount,
        rng: &mut R,
    ) -> Fallible<(PubAccount, PubAccount)> {
        ensure!(
            sndr_account.id
                == justified_transaction
                    .content
                    .content // finalized transaction data
                    .init_data
                    .content
                    .memo
                    .sndr_account_id,
            ErrorKind::AccountIdMismatch
        );
        ensure!(
            rcvr_account.id
                == justified_transaction
                    .content
                    .content // finalized transaction data
                    .init_data
                    .content
                    .memo
                    .rcvr_account_id,
            ErrorKind::AccountIdMismatch
        );
        let finalized_transaction = &justified_transaction.content;
        let initialized_transaction = &finalized_transaction.content;
        verify_initialized_transaction(
            &initialized_transaction.init_data,
            &sndr_account,
            &rcvr_account,
            pending_balance,
            rng,
        )?;
        verify_finalized_transaction(
            &finalized_transaction,
            &sndr_account,
            &rcvr_account,
            pending_balance,
            rng,
        )?;
        verify_justified_transaction(&justified_transaction, mdtr_sign_pub_key)?;

        // All verifications were successful, update the sender and receiver balances.
        let updated_sndr_account = crate::mercat::account::withdraw(
            sndr_account,
            initialized_transaction
                .init_data
                .content
                .memo
                .enc_amount_using_sndr,
        );
        let updated_rcvr_account = crate::mercat::account::deposit(
            rcvr_account,
            initialized_transaction
                .init_data
                .content
                .memo
                .enc_amount_using_rcvr,
        );

        Ok((updated_sndr_account, updated_rcvr_account))
    }
}

fn verify_initialized_transaction<R: RngCore + CryptoRng>(
    transaction: &InitializedTransferTx,
    sndr_account: &PubAccount,
    rcvr_account: &PubAccount,
    pending_balance: EncryptedAmount,
    rng: &mut R,
) -> Fallible<TxState> {
    let message = transaction.content.encode();
    let _ = sndr_account
        .memo
        .owner_sign_pub_key
        .verify(SIG_CTXT.bytes(&message), &transaction.sig)?;

    verify_initial_transaction_proofs(
        transaction,
        sndr_account,
        rcvr_account,
        pending_balance,
        rng,
    )?;

    Ok(TxState::Initialization(TxSubstate::Validated))
}

fn verify_finalized_transaction<R: RngCore + CryptoRng>(
    transaction_final_data: &FinalizedTransferTx,
    sndr_account: &PubAccount,
    rcvr_account: &PubAccount,
    pending_balance: EncryptedAmount,
    rng: &mut R,
) -> Fallible<TxState> {
    let message = transaction_final_data.content.encode();
    let _ = rcvr_account
        .memo
        .owner_sign_pub_key
        .verify(SIG_CTXT.bytes(&message), &transaction_final_data.sig)?;

    let memo = &transaction_final_data.content.init_data.content.memo;
    let init_data = &transaction_final_data.content.init_data;
    let final_content = &transaction_final_data.content;

    verify_initial_transaction_proofs(
        init_data,
        &sndr_account,
        &rcvr_account,
        pending_balance,
        rng,
    )?;

    // In the initial transaction, the sender has encrypted the asset id
    // using the receiver pub key. We verify that this encrypted asset id
    // is the same as the one in the receiver account
    single_property_verifier(
        &CipherTextRefreshmentVerifier::new(
            rcvr_account.memo.owner_enc_pub_key,
            rcvr_account.enc_asset_id,
            memo.enc_asset_id_using_rcvr,
            &PedersenGens::default(),
        ),
        final_content.asset_id_from_sndr_equal_to_rcvr_proof,
    )?;

    Ok(TxState::Finalization(TxSubstate::Validated))
}

fn verify_justified_transaction(
    transaction_justified_final_data: &JustifiedTransferTx,
    mdtr_sign_pub_key: &SigningPubKey,
) -> Fallible<TxState> {
    let ctx_data = &transaction_justified_final_data;
    let message = ctx_data.content.encode();
    let _ = mdtr_sign_pub_key.verify(SIG_CTXT.bytes(&message), &ctx_data.sig)?;

    Ok(TxState::Justification(TxSubstate::Validated))
}

fn verify_initial_transaction_proofs<R: RngCore + CryptoRng>(
    transaction: &InitializedTransferTx,
    sndr_account: &PubAccount,
    rcvr_account: &PubAccount,
    pending_balance: EncryptedAmount,
    rng: &mut R,
) -> Fallible<()> {
    let memo = &transaction.content.memo;
    let init_data = &transaction.content;
    let gens = &PedersenGens::default();

    // Verify that the encrypted amounts are equal
    single_property_verifier(
        &EncryptingSameValueVerifier {
            pub_key1: sndr_account.memo.owner_enc_pub_key,
            pub_key2: rcvr_account.memo.owner_enc_pub_key,
            cipher1: memo.enc_amount_using_sndr,
            cipher2: memo.enc_amount_using_rcvr,
            pc_gens: &gens,
        },
        init_data.amount_equal_cipher_proof,
    )?;

    // Verify that the amount is not negative
    verify_within_range(&init_data.non_neg_amount_proof, rng)?;

    // verify that the balance refreshment was done correctly
    single_property_verifier(
        &CipherTextRefreshmentVerifier::new(
            sndr_account.memo.owner_enc_pub_key,
            pending_balance,
            memo.refreshed_enc_balance,
            &gens,
        ),
        init_data.balance_refreshed_same_proof,
    )?;

    // Verify that the balance has enough fund
    verify_within_range(&init_data.enough_fund_proof, rng)?;

    // Verify that the asset id refreshment was done correctly
    single_property_verifier(
        &CipherTextRefreshmentVerifier::new(
            sndr_account.memo.owner_enc_pub_key,
            sndr_account.enc_asset_id,
            memo.refreshed_enc_asset_id,
            &gens,
        ),
        init_data.asset_id_refreshed_same_proof,
    )?;

    // In the initial transaction, the sender has encrypted the asset id
    // using the receiver pub key. We verify that this encrypted asset id
    // is the same as the one in the sender account.
    single_property_verifier(
        &EncryptingSameValueVerifier {
            pub_key1: sndr_account.memo.owner_enc_pub_key,
            pub_key2: rcvr_account.memo.owner_enc_pub_key,
            cipher1: memo.refreshed_enc_asset_id,
            cipher2: memo.enc_asset_id_using_rcvr,
            pc_gens: &gens,
        },
        init_data.asset_id_equal_cipher_with_sndr_rcvr_keys_proof,
    )?;

    Ok(())
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::{
        asset_proofs::{
            ciphertext_refreshment_proof::CipherEqualSamePubKeyProof,
            correctness_proof::CorrectnessProof, ElgamalSecretKey,
        },
        mercat::{
            AccountMemo, EncryptedAmount, EncryptedAssetId, EncryptionKeys, EncryptionPubKey,
            SecAccount, Signature, SigningKeys, SigningPubKey, TransferTxMemo,
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
    ) -> TransferTxMemo {
        let (_, enc_amount_using_rcvr) = rcvr_pub_key.encrypt_value(amount.into(), rng);
        let (_, enc_asset_id_using_rcvr) = rcvr_pub_key.encrypt_value(asset_id.into(), rng);
        TransferTxMemo {
            sndr_account_id: 0,
            rcvr_account_id: 0,
            enc_amount_using_sndr: EncryptedAmount::default(),
            enc_amount_using_rcvr: EncryptedAmount::from(enc_amount_using_rcvr),
            refreshed_enc_balance: EncryptedAmount::default(),
            refreshed_enc_asset_id: EncryptedAssetId::default(),
            enc_asset_id_using_rcvr: EncryptedAssetId::from(enc_asset_id_using_rcvr),
            enc_amount_for_mdtr: EncryptedAmount::default(),
            enc_asset_id_for_mdtr: EncryptedAssetId::default(),
            sndr_ordering_state: OrderingState::default(),
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
            id: 1,
            enc_asset_id: enc_asset_id.into(),
            enc_balance: enc_balance.into(),
            memo: AccountMemo::new(rcvr_enc_pub_key, rcvr_sign_pub_key, 2),
        })
    }

    fn mock_ctx_init_data<R: RngCore + CryptoRng>(
        rcvr_pub_key: EncryptionPubKey,
        expected_amount: Balance,
        asset_id: AssetId,
        sig: Signature,
        rng: &mut R,
    ) -> InitializedTransferTx {
        InitializedTransferTx {
            content: InitializedTransferTxContent {
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
                asset_id_witness: CommitmentWitness::from((asset_id.into(), &mut rng)),
            },
        };
        let rcvr_pending_tx_counter: i32 = 0;

        let tx_id = 0;
        let result = ctx_rcvr.finalize_by_receiver(
            tx_id,
            ctx_init_data,
            rcvr_account,
            expected_amount,
            rcvr_pending_tx_counter,
            &mut rng,
        );

        result.unwrap();
        // Correctness of the proof will be verified in the verify function
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
                asset_id_witness: CommitmentWitness::from((asset_id.into(), &mut rng)),
            },
        };
        let rcvr_pending_tx_counter: i32 = 0;

        let tx_id = 0;
        let result = ctx_rcvr.finalize_by_receiver(
            tx_id,
            ctx_init_data,
            rcvr_account,
            expected_amount,
            rcvr_pending_tx_counter,
            &mut rng,
        );

        assert_err!(
            result,
            ErrorKind::TransactionAmountMismatch { expected_amount }
        );
    }

    // ------------------------------ Test simple scenarios

    #[test]
    #[wasm_bindgen_test]
    fn test_ctx_create_finalize_validate_success() {
        let sndr = CtxSender {};
        let rcvr = CtxReceiver {};
        let mdtr = CtxMediator {};
        let tx_validator = TransactionValidator {};
        let asset_id = AssetId::from(20);
        let sndr_balance = 40;
        let rcvr_balance = 0;
        let amount = 30;
        let sndr_pending_tx_counter: i32 = 0;
        let rcvr_pending_tx_counter: i32 = 0;

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
                enc_keys: rcvr_enc_keys.clone(),
                sign_keys: rcvr_sign_keys.clone(),
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
                enc_keys: sndr_enc_keys.clone(),
                sign_keys: sndr_sign_keys.clone(),
                asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
            },
        };

        // Create the transaction and check its result and state
        let tx_id = 0;
        let result = sndr.create_transaction(
            tx_id,
            &sndr_account,
            &rcvr_account.pblc,
            &mdtr_enc_keys.pblc,
            sndr_account.pblc.enc_balance,
            amount,
            sndr_pending_tx_counter,
            &mut rng,
        );
        let ctx_init_data = result.unwrap();

        // Finalize the transaction and check its state
        let tx_id = tx_id + 1;
        let result = rcvr.finalize_by_receiver(
            tx_id,
            ctx_init_data,
            rcvr_account.clone(),
            amount,
            rcvr_pending_tx_counter,
            &mut rng,
        );
        let ctx_finalized_data = result.unwrap();

        // Justify the transaction
        let result = mdtr.justify_transaction(
            ctx_finalized_data,
            &mdtr_enc_keys,
            &mdtr_sign_keys,
            &sndr_sign_keys.public.clone(),
            &rcvr_sign_keys.public.clone(),
            asset_id,
        );
        let justified_finalized_ctx_data = result.unwrap();

        let (updated_sender_account, updated_receiver_account) = tx_validator
            .verify_transaction(
                &justified_finalized_ctx_data,
                sndr_account.pblc.clone(),
                rcvr_account.pblc,
                &mdtr_sign_keys.public,
                // in the simple case, the pending balance is the same as the account balance
                sndr_account.pblc.enc_balance,
                &mut rng,
            )
            .unwrap();

        // ----------------------- Processing
        // Check that the transferred amount is added to the receiver's account balance
        // and subtracted from sender's balance.
        assert!(sndr_enc_keys
            .scrt
            .verify(
                &updated_sender_account.enc_balance,
                &Scalar::from(sndr_balance - amount)
            )
            .is_ok());
        assert!(rcvr_enc_keys
            .scrt
            .verify(
                &updated_receiver_account.enc_balance,
                &Scalar::from(rcvr_balance + amount)
            )
            .is_ok());
    }
}
