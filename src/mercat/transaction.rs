use crate::{
    asset_proofs::{
        ciphertext_refreshment_proof::{
            CipherTextRefreshmentProverAwaitingChallenge, CipherTextRefreshmentVerifier,
        },
        correctness_proof::{CorrectnessProverAwaitingChallenge, CorrectnessVerifier},
        elgamal_encryption::encrypt_using_two_pub_keys,
        encrypting_same_value_proof::{
            EncryptingSameValueProverAwaitingChallenge, EncryptingSameValueVerifier,
        },
        encryption_proofs::single_property_prover,
        encryption_proofs::single_property_verifier,
        range_proof::{prove_within_range, verify_within_range},
        CommitmentWitness,
    },
    errors::{ErrorKind, Fallible},
    mercat::{
        Account, AuditorPayload, EncryptedAmount, EncryptionKeys, EncryptionPubKey,
        FinalizedTransferTx, InitializedTransferTx, JustifiedTransferTx, PubAccount,
        TransferTransactionAuditor, TransferTransactionMediator, TransferTransactionReceiver,
        TransferTransactionSender, TransferTransactionVerifier, TransferTxMemo, TransferTxState,
        TxSubstate,
    },
    AssetId, Balance, BALANCE_RANGE,
};

use bulletproofs::PedersenGens;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sp_std::vec::Vec;
use zeroize::Zeroizing;

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
        sndr_init_balance: &EncryptedAmount,
        rcvr_pub_account: &PubAccount,
        mdtr_pub_key: &EncryptionPubKey,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<InitializedTransferTx> {
        let sndr_enc_keys = &sndr_account.scrt.enc_keys;
        let asset_id = sndr_account.scrt.asset_id_witness.value();
        let sndr_pub_account = &sndr_account.pblc;
        let rcvr_pub_key = rcvr_pub_account.owner_enc_pub_key;

        // NOTE: If this decryption ends up being too slow, we can pass in the balance
        // as input.
        let balance = sndr_enc_keys.scrt.decrypt(sndr_init_balance)?;
        ensure!(
            balance >= amount,
            ErrorKind::NotEnoughFund {
                balance,
                transaction_amount: amount
            }
        );

        // Prove that the amount is not negative.
        let witness = CommitmentWitness::new(amount.into(), Scalar::random(rng));
        let amount_enc_blinding = witness.blinding();

        let non_neg_amount_proof =
            prove_within_range(amount.into(), amount_enc_blinding, BALANCE_RANGE, rng)?;

        // Prove that the amount encrypted under different public keys are the same.
        let (sndr_new_enc_amount, rcvr_new_enc_amount) =
            encrypt_using_two_pub_keys(&witness, sndr_enc_keys.pblc, rcvr_pub_key);
        let gens = PedersenGens::default();
        let amount_equal_cipher_proof = single_property_prover(
            EncryptingSameValueProverAwaitingChallenge {
                pub_key1: sndr_enc_keys.pblc,
                pub_key2: rcvr_pub_key,
                w: Zeroizing::new(witness.clone()),
                pc_gens: &gens,
            },
            rng,
        )?;

        // Refresh the encrypted balance and prove that the refreshment was done
        // correctly.
        let balance_refresh_enc_blinding = Scalar::random(rng);
        let refreshed_enc_balance =
            sndr_init_balance.refresh(&sndr_enc_keys.scrt, balance_refresh_enc_blinding)?;

        let balance_refreshed_same_proof = single_property_prover(
            CipherTextRefreshmentProverAwaitingChallenge::new(
                sndr_enc_keys.scrt.clone(),
                *sndr_init_balance,
                refreshed_enc_balance,
                &gens,
            ),
            rng,
        )?;

        // Prove that the sender has enough funds.
        let blinding = balance_refresh_enc_blinding - amount_enc_blinding;
        let enough_fund_proof =
            prove_within_range((balance - amount).into(), blinding, BALANCE_RANGE, rng)?;

        // Refresh the encrypted asset id of the sender account and prove that the
        // refreshment was done correctly.
        let asset_id_refresh_enc_blinding = Scalar::random(rng);
        let refreshed_enc_asset_id = sndr_pub_account.enc_asset_id.refresh_with_hint(
            &sndr_enc_keys.scrt,
            asset_id_refresh_enc_blinding,
            &asset_id.clone(),
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
        // encrypted by the receiver's pub key.
        let asset_id_witness_for_rcvr =
            CommitmentWitness::new(asset_id, asset_id_refresh_enc_blinding);
        let enc_asset_id_using_rcvr = rcvr_pub_key.encrypt(&asset_id_witness_for_rcvr);
        let asset_id_equal_cipher_with_sndr_rcvr_keys_proof = single_property_prover(
            EncryptingSameValueProverAwaitingChallenge {
                pub_key1: sndr_enc_keys.pblc,
                pub_key2: rcvr_pub_key,
                w: Zeroizing::new(asset_id_witness_for_rcvr.clone()),
                pc_gens: &gens,
            },
            rng,
        )?;

        // Prepare the correctness proofs for the mediator.
        let asset_id_witness_blinding_for_mdtr = Scalar::random(rng);
        let asset_id_witness_for_mdtr =
            CommitmentWitness::new(asset_id, asset_id_witness_blinding_for_mdtr);
        let enc_asset_id_for_mdtr = mdtr_pub_key.encrypt(&asset_id_witness_for_mdtr);

        let amount_witness_blinding_for_mdtr = Scalar::random(rng);
        let amount_witness_for_mdtr =
            CommitmentWitness::new(amount.into(), amount_witness_blinding_for_mdtr);
        let enc_amount_for_mdtr = mdtr_pub_key.const_time_encrypt(&amount_witness_for_mdtr, rng);

        let asset_id_correctness_proof = single_property_prover(
            CorrectnessProverAwaitingChallenge {
                pub_key: rcvr_pub_key,
                w: asset_id_witness_for_rcvr,
                pc_gens: &gens,
            },
            rng,
        )?;

        let amount_correctness_proof = single_property_prover(
            CorrectnessProverAwaitingChallenge {
                pub_key: sndr_enc_keys.pblc,
                w: witness.clone(),
                pc_gens: &gens,
            },
            rng,
        )?;

        // Add the necessary payload for auditors.
        let auditors_payload =
            add_transaction_auditor(auditors_enc_pub_keys, &sndr_enc_keys.pblc, &witness, rng)?;

        Ok(InitializedTransferTx {
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
                enc_amount_using_sndr: sndr_new_enc_amount,
                enc_amount_using_rcvr: rcvr_new_enc_amount,
                refreshed_enc_balance,
                refreshed_enc_asset_id,
                enc_asset_id_using_rcvr,
                enc_asset_id_for_mdtr,
                enc_amount_for_mdtr,
                tx_id,
            },
            auditors_payload,
        })
    }
}

fn add_transaction_auditor<T: RngCore + CryptoRng>(
    auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
    sender_enc_pub_key: &EncryptionPubKey,
    amount_witness: &CommitmentWitness,
    rng: &mut T,
) -> Fallible<Vec<AuditorPayload>> {
    let gens = PedersenGens::default();

    let mut payload_vec: Vec<AuditorPayload> = Vec::with_capacity(auditors_enc_pub_keys.len());
    // Add the required payload for the auditors.
    let _: Fallible<()> = auditors_enc_pub_keys
        .iter()
        .map(|(auditor_id, auditor_enc_pub_key)| {
            let encrypted_amount = auditor_enc_pub_key.const_time_encrypt(amount_witness, rng);

            // Prove that the sender and auditor's ciphertexts are encrypting the same
            // commitment witness.
            let amount_equal_cipher_proof = single_property_prover(
                EncryptingSameValueProverAwaitingChallenge {
                    pub_key1: *sender_enc_pub_key,
                    pub_key2: *auditor_enc_pub_key,
                    w: Zeroizing::new(amount_witness.clone()),
                    pc_gens: &gens,
                },
                rng,
            )?;

            let payload = AuditorPayload {
                auditor_id: *auditor_id,
                encrypted_amount,
                amount_equal_cipher_proof,
            };

            payload_vec.push(payload);
            Ok(())
        })
        .collect();

    Ok(payload_vec)
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
        rcvr_account: Account,
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<FinalizedTransferTx> {
        ensure!(
            tx_id == initialized_transaction.memo.tx_id,
            ErrorKind::TransactionIdMismatch
        );

        let rcvr_enc_sec = &rcvr_account.scrt.enc_keys.scrt;
        let rcvr_pub_account = &rcvr_account.pblc;

        // Check that the amount is correct.
        rcvr_enc_sec
            .verify(
                &initialized_transaction.memo.enc_amount_using_rcvr,
                &amount.into(),
            )
            .map_err(|_| ErrorKind::TransactionAmountMismatch {
                expected_amount: amount,
            })?;

        // Generate proof of equality of asset ids.
        let enc_asset_id_from_sndr = initialized_transaction.memo.enc_asset_id_using_rcvr;
        let enc_asset_id_from_rcvr_acc = rcvr_pub_account.enc_asset_id;
        let gens = PedersenGens::default();
        let prover = CipherTextRefreshmentProverAwaitingChallenge::new(
            rcvr_enc_sec.clone(),
            enc_asset_id_from_rcvr_acc,
            enc_asset_id_from_sndr,
            &gens,
        );

        let proof = single_property_prover(prover, rng)?;

        Ok(FinalizedTransferTx {
            init_data: initialized_transaction,
            asset_id_from_sndr_equal_to_rcvr_proof: proof,
        })
    }
}

// ------------------------------------------------------------------------------------------------
// -                                           Mediator                                           -
// ------------------------------------------------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct CtxMediator {}

impl TransferTransactionMediator for CtxMediator {
    fn justify_transaction<R: RngCore + CryptoRng>(
        &self,
        finalized_transaction: FinalizedTransferTx,
        mdtr_enc_keys: &EncryptionKeys,
        sndr_account: &PubAccount,
        sndr_init_balance: &EncryptedAmount,
        rcvr_account: &PubAccount,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
        asset_id_hint: AssetId,
        rng: &mut R,
    ) -> Fallible<JustifiedTransferTx> {
        // Verify receiver's part of the transaction.
        let _ = verify_finalized_transaction(&finalized_transaction, rcvr_account)?;

        // Verify sender's part of the transaction.
        // This includes checking the auditors' payload.
        let init_tx_data = &finalized_transaction.init_data;
        let _ = verify_initialized_transaction(
            &init_tx_data,
            sndr_account,
            sndr_init_balance,
            rcvr_account,
            auditors_enc_pub_keys,
            rng,
        )?;

        let gens = &PedersenGens::default();
        let tx_data = &init_tx_data;

        // Verify that the encrypted amount is correct.
        let amount = mdtr_enc_keys
            .scrt
            .const_time_decrypt(&tx_data.memo.enc_amount_for_mdtr)?;
        single_property_verifier(
            &CorrectnessVerifier {
                value: amount.into(),
                pub_key: sndr_account.owner_enc_pub_key,
                cipher: tx_data.memo.enc_amount_using_sndr,
                pc_gens: &gens,
            },
            tx_data.amount_correctness_proof,
        )?;

        // Verify that the encrypted asset_id is correct.
        mdtr_enc_keys.scrt.verify(
            &tx_data.memo.enc_asset_id_for_mdtr,
            &asset_id_hint.clone().into(),
        )?;

        let asset_id = asset_id_hint;
        single_property_verifier(
            &CorrectnessVerifier {
                value: asset_id.into(),
                pub_key: rcvr_account.owner_enc_pub_key,
                cipher: tx_data.memo.enc_asset_id_using_rcvr,
                pc_gens: &gens,
            },
            tx_data.asset_id_correctness_proof,
        )?;

        Ok(JustifiedTransferTx {
            finalized_data: finalized_transaction,
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
        sndr_account: &PubAccount,
        sndr_init_balance: &EncryptedAmount,
        rcvr_account: &PubAccount,
        rcvr_init_balance: &EncryptedAmount,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
        rng: &mut R,
    ) -> Fallible<(EncryptedAmount, EncryptedAmount)> {
        ensure!(
            sndr_account.id
                == justified_transaction
                    .finalized_data
                    .init_data
                    .memo
                    .sndr_account_id,
            ErrorKind::AccountIdMismatch
        );
        ensure!(
            rcvr_account.id
                == justified_transaction
                    .finalized_data
                    .init_data
                    .memo
                    .rcvr_account_id,
            ErrorKind::AccountIdMismatch
        );
        let finalized_transaction = &justified_transaction.finalized_data;
        let initialized_transaction = &finalized_transaction.init_data;
        verify_initialized_transaction(
            &initialized_transaction,
            sndr_account,
            sndr_init_balance,
            rcvr_account,
            auditors_enc_pub_keys,
            rng,
        )?;

        verify_finalized_transaction(&finalized_transaction, rcvr_account)?;

        // All verifications were successful, update the sender and receiver balances.
        let updated_sndr_balance = crate::mercat::account::withdraw(
            sndr_init_balance,
            &initialized_transaction.memo.enc_amount_using_sndr,
        );
        let updated_rcvr_balance = crate::mercat::account::deposit(
            rcvr_init_balance,
            &initialized_transaction.memo.enc_amount_using_rcvr,
        );

        Ok((updated_sndr_balance, updated_rcvr_balance))
    }
}

fn verify_initialized_transaction<R: RngCore + CryptoRng>(
    transaction: &InitializedTransferTx,
    sndr_account: &PubAccount,
    sndr_init_balance: &EncryptedAmount,
    rcvr_account: &PubAccount,
    auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
    rng: &mut R,
) -> Fallible<TransferTxState> {
    verify_initial_transaction_proofs(
        transaction,
        sndr_account,
        sndr_init_balance,
        rcvr_account,
        auditors_enc_pub_keys,
        rng,
    )?;

    Ok(TransferTxState::Initialization(TxSubstate::Validated))
}

fn verify_finalized_transaction(
    transaction_final_data: &FinalizedTransferTx,
    rcvr_account: &PubAccount,
) -> Fallible<TransferTxState> {
    let memo = &transaction_final_data.init_data.memo;

    // In the initial transaction, the sender has encrypted the asset id
    // using the receiver pub key. We verify that this encrypted asset id
    // is the same as the one in the receiver account
    single_property_verifier(
        &CipherTextRefreshmentVerifier::new(
            rcvr_account.owner_enc_pub_key,
            rcvr_account.enc_asset_id,
            memo.enc_asset_id_using_rcvr,
            &PedersenGens::default(),
        ),
        transaction_final_data.asset_id_from_sndr_equal_to_rcvr_proof,
    )?;

    Ok(TransferTxState::Finalization(TxSubstate::Validated))
}

fn verify_initial_transaction_proofs<R: RngCore + CryptoRng>(
    transaction: &InitializedTransferTx,
    sndr_account: &PubAccount,
    sndr_init_balance: &EncryptedAmount,
    rcvr_account: &PubAccount,
    auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
    rng: &mut R,
) -> Fallible<()> {
    let memo = &transaction.memo;
    let init_data = &transaction;
    let gens = &PedersenGens::default();

    // Verify that the encrypted amounts are equal.
    single_property_verifier(
        &EncryptingSameValueVerifier {
            pub_key1: sndr_account.owner_enc_pub_key,
            pub_key2: rcvr_account.owner_enc_pub_key,
            cipher1: memo.enc_amount_using_sndr,
            cipher2: memo.enc_amount_using_rcvr,
            pc_gens: &gens,
        },
        init_data.amount_equal_cipher_proof,
    )?;

    // Verify that the amount is not negative.
    verify_within_range(&init_data.non_neg_amount_proof, rng)?;

    // verify that the balance refreshment was done correctly.
    single_property_verifier(
        &CipherTextRefreshmentVerifier::new(
            sndr_account.owner_enc_pub_key,
            *sndr_init_balance,
            memo.refreshed_enc_balance,
            &gens,
        ),
        init_data.balance_refreshed_same_proof,
    )?;

    // Verify that the balance has enough fund.
    verify_within_range(&init_data.enough_fund_proof, rng)?;

    // Verify that the asset id refreshment was done correctly.
    single_property_verifier(
        &CipherTextRefreshmentVerifier::new(
            sndr_account.owner_enc_pub_key,
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
            pub_key1: sndr_account.owner_enc_pub_key,
            pub_key2: rcvr_account.owner_enc_pub_key,
            cipher1: memo.refreshed_enc_asset_id,
            cipher2: memo.enc_asset_id_using_rcvr,
            pc_gens: &gens,
        },
        init_data.asset_id_equal_cipher_with_sndr_rcvr_keys_proof,
    )?;

    // Verify that all auditors' payload is included, and
    // that the auditors' ciphertexts encrypt the same amount as sender's ciphertext.
    verify_auditor_payload(
        &init_data.auditors_payload,
        auditors_enc_pub_keys,
        sndr_account.owner_enc_pub_key,
        init_data.memo.enc_amount_using_sndr,
    )?;

    Ok(())
}

fn verify_auditor_payload(
    auditors_payload: &[AuditorPayload],
    auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
    sender_enc_pub_key: EncryptionPubKey,
    sender_enc_amount: EncryptedAmount,
) -> Fallible<()> {
    ensure!(
        auditors_payload.len() == auditors_enc_pub_keys.len(),
        ErrorKind::AuditorPayloadError
    );

    let gens = &PedersenGens::default();
    let _: Fallible<()> = auditors_enc_pub_keys
        .iter()
        .map(|(auditor_id, auditor_pub_key)| {
            let mut found_auditor = false;
            let _: Fallible<()> = auditors_payload
                .iter()
                .map(|payload| {
                    if *auditor_id == payload.auditor_id {
                        // Verify that the encrypted amounts are equal.
                        single_property_verifier(
                            &EncryptingSameValueVerifier {
                                pub_key1: sender_enc_pub_key,
                                pub_key2: *auditor_pub_key,
                                cipher1: sender_enc_amount,
                                cipher2: payload.encrypted_amount.elgamal_cipher,
                                pc_gens: &gens,
                            },
                            payload.amount_equal_cipher_proof,
                        )?;
                        found_auditor |= true;
                    }
                    Ok(())
                })
                .collect();
            ensure!(found_auditor, ErrorKind::AuditorPayloadError);
            Ok(())
        })
        .collect();

    Ok(())
}

// ------------------------------------------------------------------------------------------------
// -                                          Auditor                                           -
// ------------------------------------------------------------------------------------------------

/// Transaction Validator.
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct CtxAuditor {}

impl TransferTransactionAuditor for CtxAuditor {
    /// Verify the initialized, finalized, and justified transactions.
    /// Audit the sender's encrypted amount.
    fn audit_transaction(
        &self,
        justified_transaction: &JustifiedTransferTx,
        sndr_account: &PubAccount,
        rcvr_account: &PubAccount,
        auditor_enc_key: &(u32, EncryptionKeys),
    ) -> Fallible<()> {
        ensure!(
            sndr_account.id
                == justified_transaction
                    .finalized_data
                    .init_data
                    .memo
                    .sndr_account_id,
            ErrorKind::AccountIdMismatch
        );
        ensure!(
            rcvr_account.id
                == justified_transaction
                    .finalized_data
                    .init_data
                    .memo
                    .rcvr_account_id,
            ErrorKind::AccountIdMismatch
        );

        let gens = &PedersenGens::default();
        let finalized_transaction = &justified_transaction.finalized_data;
        let initialized_transaction = &finalized_transaction.init_data;

        verify_finalized_transaction(&finalized_transaction, &rcvr_account)?;

        // If all checks pass, decrypt the encrypted amount and verify sender's correctness proof.
        let _: Fallible<()> = initialized_transaction
            .auditors_payload
            .iter()
            .map(|payload| {
                if payload.auditor_id == auditor_enc_key.0 {
                    let amount = auditor_enc_key
                        .1
                        .scrt
                        .const_time_decrypt(&payload.encrypted_amount)?;

                    let result = single_property_verifier(
                        &CorrectnessVerifier {
                            value: amount.into(),
                            pub_key: sndr_account.owner_enc_pub_key,
                            cipher: initialized_transaction.memo.enc_amount_using_sndr,
                            pc_gens: &gens,
                        },
                        initialized_transaction.amount_correctness_proof,
                    );
                    return result;
                }
                Ok(())
            })
            .collect();

        Err(ErrorKind::AuditorPayloadError.into())
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
        asset_proofs::{
            ciphertext_refreshment_proof::CipherEqualSamePubKeyProof,
            correctness_proof::CorrectnessProof,
            encrypting_same_value_proof::CipherEqualDifferentPubKeyProof,
            range_proof::InRangeProof, ElgamalSecretKey,
        },
        mercat::{
            EncryptedAmount, EncryptedAmountWithHint, EncryptedAssetId, EncryptionKeys,
            EncryptionPubKey, SecAccount, TransferTxMemo,
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
            pblc: elg_pub,
            scrt: elg_secret,
        }
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
            enc_amount_using_rcvr,
            refreshed_enc_balance: EncryptedAmount::default(),
            refreshed_enc_asset_id: EncryptedAssetId::default(),
            enc_asset_id_using_rcvr,
            enc_asset_id_for_mdtr: EncryptedAssetId::default(),
            enc_amount_for_mdtr: EncryptedAmountWithHint::default(),
            tx_id: 0,
        }
    }

    fn mock_gen_account<R: RngCore + CryptoRng>(
        rcvr_enc_pub_key: EncryptionPubKey,
        asset_id: AssetId,
        balance: Balance,
        rng: &mut R,
    ) -> Fallible<(PubAccount, EncryptedAmount)> {
        let (_, enc_asset_id) = rcvr_enc_pub_key.encrypt_value(asset_id.into(), rng);
        let (_, enc_balance) = rcvr_enc_pub_key.encrypt_value(Scalar::from(balance), rng);

        Ok((
            PubAccount {
                id: 1,
                enc_asset_id,
                owner_enc_pub_key: rcvr_enc_pub_key,
            },
            enc_balance,
        ))
    }

    fn mock_ctx_init_data<R: RngCore + CryptoRng>(
        rcvr_pub_key: EncryptionPubKey,
        expected_amount: Balance,
        asset_id: AssetId,
        rng: &mut R,
    ) -> InitializedTransferTx {
        InitializedTransferTx {
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
            auditors_payload: [].to_vec(),
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

        let ctx_init_data = mock_ctx_init_data(
            rcvr_enc_keys.pblc,
            expected_amount,
            asset_id.clone(),
            &mut rng,
        );
        let (pub_account, _enc_balance) =
            mock_gen_account(rcvr_enc_keys.pblc, asset_id.clone(), balance, &mut rng).unwrap();
        let rcvr_account = Account {
            pblc: pub_account,
            scrt: SecAccount {
                enc_keys: rcvr_enc_keys,
                asset_id_witness: CommitmentWitness::from((asset_id.into(), &mut rng)),
            },
        };

        let tx_id = 0;
        let result = ctx_rcvr.finalize_transaction(
            tx_id,
            ctx_init_data,
            rcvr_account,
            expected_amount,
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

        let ctx_init_data = mock_ctx_init_data(
            rcvr_enc_keys.pblc,
            received_amount,
            asset_id.clone(),
            &mut rng,
        );
        let rcvr_account = Account {
            pblc: mock_gen_account(rcvr_enc_keys.pblc, asset_id.clone(), balance, &mut rng)
                .unwrap()
                .0,
            scrt: SecAccount {
                enc_keys: rcvr_enc_keys,
                asset_id_witness: CommitmentWitness::from((asset_id.into(), &mut rng)),
            },
        };

        let tx_id = 0;
        let result = ctx_rcvr.finalize_transaction(
            tx_id,
            ctx_init_data,
            rcvr_account,
            expected_amount,
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

        let mut rng = StdRng::from_seed([17u8; 32]);

        let sndr_enc_keys = mock_gen_enc_key_pair(10u8);

        let rcvr_enc_keys = mock_gen_enc_key_pair(12u8);

        let mdtr_enc_keys = mock_gen_enc_key_pair(14u8);

        let (rcvr_pub_account, rcvr_init_balance) =
            mock_gen_account(rcvr_enc_keys.pblc, asset_id.clone(), rcvr_balance, &mut rng).unwrap();
        let rcvr_account = Account {
            pblc: rcvr_pub_account,
            scrt: SecAccount {
                enc_keys: rcvr_enc_keys.clone(),
                asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
            },
        };

        let (sndr_pub_account, sndr_init_balance) =
            mock_gen_account(sndr_enc_keys.pblc, asset_id.clone(), sndr_balance, &mut rng).unwrap();
        let sndr_account = Account {
            pblc: sndr_pub_account,
            scrt: SecAccount {
                enc_keys: sndr_enc_keys.clone(),
                asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
            },
        };

        // Create the transaction and check its result and state
        let tx_id = 0;
        let result = sndr.create_transaction(
            tx_id,
            &sndr_account,
            &sndr_init_balance,
            &rcvr_account.pblc,
            &mdtr_enc_keys.pblc,
            &[],
            amount,
            &mut rng,
        );
        let ctx_init_data = result.unwrap();

        // Finalize the transaction and check its state
        let result =
            rcvr.finalize_transaction(tx_id, ctx_init_data, rcvr_account.clone(), amount, &mut rng);
        let ctx_finalized_data = result.unwrap();

        // Justify the transaction
        let result = mdtr.justify_transaction(
            ctx_finalized_data,
            &mdtr_enc_keys,
            &sndr_account.pblc,
            &sndr_init_balance,
            &rcvr_account.pblc,
            &[],
            asset_id,
            &mut rng,
        );
        let justified_finalized_ctx_data = result.unwrap();

        let (updated_sender_balance, updated_receiver_balance) = tx_validator
            .verify_transaction(
                &justified_finalized_ctx_data,
                &sndr_account.pblc,
                &sndr_init_balance,
                &rcvr_account.pblc,
                &rcvr_init_balance,
                &[],
                &mut rng,
            )
            .unwrap();

        // ----------------------- Processing
        // Check that the transferred amount is added to the receiver's account balance
        // and subtracted from sender's balance.
        assert!(sndr_enc_keys
            .scrt
            .verify(&updated_sender_balance, &(sndr_balance - amount).into())
            .is_ok());
        assert!(rcvr_enc_keys
            .scrt
            .verify(&updated_receiver_balance, &(rcvr_balance + amount).into())
            .is_ok());
    }

    // ------------------------------ Test Auditing Logic
    fn account_create_helper(
        seed0: [u8; 32],
        seed1: u8,
        balance: Balance,
        asset_id: AssetId,
    ) -> (Account, EncryptedAmount) {
        let mut rng = StdRng::from_seed(seed0);

        let enc_keys = mock_gen_enc_key_pair(seed1);

        let (pub_account, init_balance) =
            mock_gen_account(enc_keys.pblc, asset_id.clone(), balance, &mut rng).unwrap();

        (
            Account {
                pblc: pub_account,
                scrt: SecAccount {
                    enc_keys,
                    asset_id_witness: CommitmentWitness::from((asset_id.into(), &mut rng)),
                },
            },
            init_balance,
        )
    }

    fn test_transaction_auditor_helper(
        sender_auditor_list: &[(u32, EncryptionPubKey)],
        mediator_auditor_list: &[(u32, EncryptionPubKey)],
        mediator_check_fails: bool,
        validator_auditor_list: &[(u32, EncryptionPubKey)],
        validator_check_fails: bool,
        auditors_list: &[(u32, EncryptionKeys)],
    ) {
        let sndr = CtxSender {};
        let rcvr = CtxReceiver {};
        let mdtr = CtxMediator {};
        let validator = TransactionValidator {};
        let asset_id = AssetId::from(20);
        let sndr_balance = 500;
        let rcvr_balance = 0;
        let amount = 400;

        let mut rng = StdRng::from_seed([19u8; 32]);

        let mdtr_enc_keys = mock_gen_enc_key_pair(140u8);

        let (rcvr_account, rcvr_init_balance) =
            account_create_helper([18u8; 32], 120u8, rcvr_balance, asset_id.clone());

        let (sndr_account, sndr_init_balance) =
            account_create_helper([17u8; 32], 100u8, sndr_balance, asset_id.clone());

        // Create the transaction and check its result and state
        let tx_id = 0;
        let ctx_init = sndr
            .create_transaction(
                tx_id,
                &sndr_account,
                &sndr_init_balance,
                &rcvr_account.pblc,
                &mdtr_enc_keys.pblc,
                sender_auditor_list,
                amount,
                &mut rng,
            )
            .unwrap();

        // Finalize the transaction and check its state
        let ctx_final = rcvr
            .finalize_transaction(tx_id, ctx_init, rcvr_account.clone(), amount, &mut rng)
            .unwrap();

        // Justify the transaction
        let result = mdtr.justify_transaction(
            ctx_final,
            &mdtr_enc_keys,
            &sndr_account.pblc,
            &sndr_init_balance,
            &rcvr_account.pblc,
            mediator_auditor_list,
            asset_id,
            &mut rng,
        );

        if mediator_check_fails {
            assert_err!(result, ErrorKind::AuditorPayloadError);
            return;
        }

        let ctx_just = result.unwrap();
        let result = validator.verify_transaction(
            &ctx_just,
            &sndr_account.pblc,
            &sndr_init_balance,
            &rcvr_account.pblc,
            &rcvr_init_balance,
            validator_auditor_list,
            &mut rng,
        );

        if validator_check_fails {
            assert_err!(result, ErrorKind::AuditorPayloadError);
            return;
        }

        let (updated_sender_balance, updated_receiver_balance) = result.unwrap();

        // ----------------------- Processing
        // Check that the transferred amount is added to the receiver's account balance
        // and subtracted from sender's balance.
        assert!(sndr_account
            .scrt
            .enc_keys
            .scrt
            .verify(&updated_sender_balance, &(sndr_balance - amount).into())
            .is_ok());
        assert!(rcvr_account
            .scrt
            .enc_keys
            .scrt
            .verify(&updated_receiver_balance, &(rcvr_balance + amount).into())
            .is_ok());

        // ----------------------- Auditing
        let _ = auditors_list.iter().map(|auditor| {
            let transaction_auditor = CtxAuditor {};
            assert!(transaction_auditor
                .audit_transaction(&ctx_just, &sndr_account.pblc, &rcvr_account.pblc, auditor,)
                .is_ok());
        });
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_transaction_auditor() {
        // Make imaginary auditors.
        let auditors_num = 5u32;
        let auditors_secret_vec: Vec<(u32, EncryptionKeys)> = (0..auditors_num)
            .map(|index| {
                let auditor_keys = mock_gen_enc_key_pair(index as u8);
                (index, auditor_keys)
            })
            .collect();
        let auditors_secret_list = auditors_secret_vec.as_slice();

        let auditors_vec: Vec<(u32, EncryptionPubKey)> = auditors_secret_vec
            .iter()
            .map(|a| (a.0, a.1.pblc))
            .collect();

        let auditors_list = auditors_vec.as_slice();

        // Positive tests.

        // Include `auditors_num` auditors.
        test_transaction_auditor_helper(
            auditors_list,
            auditors_list,
            false,
            auditors_list,
            false,
            auditors_secret_list,
        );

        // Change the order of auditors lists on the mediator and validator sides.
        // The tests still must pass.
        let mediator_auditor_list = vec![
            auditors_vec[1],
            auditors_vec[0],
            auditors_vec[3],
            auditors_vec[2],
            auditors_vec[4],
        ];
        let validator_auditor_list = vec![
            auditors_vec[4],
            auditors_vec[3],
            auditors_vec[2],
            auditors_vec[1],
            auditors_vec[0],
        ];

        let mediator_auditor_list = mediator_auditor_list;
        let validator_auditor_list = validator_auditor_list;

        test_transaction_auditor_helper(
            auditors_list,
            &mediator_auditor_list,
            false,
            &validator_auditor_list,
            false,
            auditors_secret_list,
        );

        // Asset doesn't have any auditors.
        test_transaction_auditor_helper(&[], &[], false, &[], false, &[]);

        // Negative tests.

        // Sender misses an auditor. Mediator catches it.
        let four_auditor_list = vec![
            auditors_vec[1],
            auditors_vec[0],
            auditors_vec[3],
            auditors_vec[2],
        ];
        let four_auditor_list = four_auditor_list.as_slice();

        test_transaction_auditor_helper(
            four_auditor_list,
            &mediator_auditor_list,
            true,
            &validator_auditor_list,
            true,
            auditors_secret_list,
        );

        // Sender and mediator miss an auditor, but validator catches them.
        test_transaction_auditor_helper(
            four_auditor_list,
            four_auditor_list,
            false,
            &validator_auditor_list,
            true,
            auditors_secret_list,
        );

        // Sender doesn't include any auditors. Mediator catches it.
        test_transaction_auditor_helper(
            &[],
            &mediator_auditor_list,
            true,
            &validator_auditor_list,
            true,
            auditors_secret_list,
        );

        // Sender and mediator don't believe in auditors but validator does.
        test_transaction_auditor_helper(
            &[],
            &[],
            false,
            &validator_auditor_list,
            true,
            auditors_secret_list,
        );
    }
}
