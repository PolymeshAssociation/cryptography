use crate::{
    Account, AuditorPayload, EncryptedAmount, EncryptionKeys, EncryptionPubKey,
    FinalizedTransferTx, InitializedTransferTx, JustifiedTransferTx, PubAccount,
    TransferTransactionAuditor, TransferTransactionMediator, TransferTransactionReceiver,
    TransferTransactionSender, TransferTransactionVerifier, TransferTxMemo, TransferTxState,
    TxSubstate,
};
use confidential_identity_core::{
    asset_proofs::{
        bulletproofs::PedersenGens,
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
        errors::{ErrorKind, Fallible},
        range_proof::{prove_within_range, verify_within_range},
        AssetId, Balance, CommitmentWitness, BALANCE_RANGE,
    },
    curve25519_dalek::scalar::Scalar,
};

use rand_core::{CryptoRng, RngCore};
use sp_std::vec::Vec;
use zeroize::Zeroizing;

// -------------------------------------------------------------------------------------
// -                                    Sender                                         -
// -------------------------------------------------------------------------------------

/// The sender of a confidential transaction. Sender creates a transaction
/// and performs initial proofs.
#[derive(Clone, Debug)]
pub struct CtxSender;

impl TransferTransactionSender for CtxSender {
    fn create_transaction<T: RngCore + CryptoRng>(
        &self,
        sender_account: &Account,
        sender_init_balance: &EncryptedAmount,
        receiver_pub_account: &PubAccount,
        mediator_pub_key: &EncryptionPubKey,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<InitializedTransferTx> {
        let sender_enc_keys = &sender_account.secret.enc_keys;
        let asset_id = sender_account.secret.asset_id_witness.value();
        let sender_pub_account = &sender_account.public;
        let receiver_pub_key = receiver_pub_account.owner_enc_pub_key;

        // NOTE: If this decryption ends up being too slow, we can pass in the balance
        // as input.
        let balance = sender_enc_keys.secret.decrypt(sender_init_balance)?;
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
        let (sender_new_enc_amount, receiver_new_enc_amount) =
            encrypt_using_two_pub_keys(&witness, sender_enc_keys.public, receiver_pub_key);
        let gens = PedersenGens::default();
        let amount_equal_cipher_proof = single_property_prover(
            EncryptingSameValueProverAwaitingChallenge {
                pub_key1: sender_enc_keys.public,
                pub_key2: receiver_pub_key,
                w: Zeroizing::new(witness.clone()),
                pc_gens: &gens,
            },
            rng,
        )?;

        // Refresh the encrypted balance and prove that the refreshment was done
        // correctly.
        let balance_refresh_enc_blinding = Scalar::random(rng);
        let refreshed_enc_balance =
            sender_init_balance.refresh(&sender_enc_keys.secret, balance_refresh_enc_blinding)?;

        let balance_refreshed_same_proof = single_property_prover(
            CipherTextRefreshmentProverAwaitingChallenge::new(
                sender_enc_keys.secret.clone(),
                *sender_init_balance,
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
        let refreshed_enc_asset_id = sender_pub_account.enc_asset_id.refresh_with_hint(
            &sender_enc_keys.secret,
            asset_id_refresh_enc_blinding,
            &asset_id.clone(),
        )?;

        let asset_id_refreshed_same_proof = single_property_prover(
            CipherTextRefreshmentProverAwaitingChallenge::new(
                sender_enc_keys.secret.clone(),
                sender_pub_account.enc_asset_id,
                refreshed_enc_asset_id,
                &gens,
            ),
            rng,
        )?;

        // Prove the new refreshed encrypted asset id is the same as the one
        // encrypted by the receiver's pub key.
        let asset_id_witness_for_receiver =
            CommitmentWitness::new(asset_id, asset_id_refresh_enc_blinding);
        let enc_asset_id_using_receiver = receiver_pub_key.encrypt(&asset_id_witness_for_receiver);
        let asset_id_equal_cipher_with_sender_receiver_keys_proof = single_property_prover(
            EncryptingSameValueProverAwaitingChallenge {
                pub_key1: sender_enc_keys.public,
                pub_key2: receiver_pub_key,
                w: Zeroizing::new(asset_id_witness_for_receiver.clone()),
                pc_gens: &gens,
            },
            rng,
        )?;

        // Prepare the correctness proofs for the mediator.
        let asset_id_witness_blinding_for_mediator = Scalar::random(rng);
        let asset_id_witness_for_mediator =
            CommitmentWitness::new(asset_id, asset_id_witness_blinding_for_mediator);
        let enc_asset_id_for_mediator = mediator_pub_key.encrypt(&asset_id_witness_for_mediator);

        let amount_witness_blinding_for_mediator = Scalar::random(rng);
        let amount_witness_for_mediator =
            CommitmentWitness::new(amount.into(), amount_witness_blinding_for_mediator);
        let enc_amount_for_mediator =
            mediator_pub_key.const_time_encrypt(&amount_witness_for_mediator, rng);

        let asset_id_correctness_proof = single_property_prover(
            CorrectnessProverAwaitingChallenge {
                pub_key: receiver_pub_key,
                w: asset_id_witness_for_receiver,
                pc_gens: &gens,
            },
            rng,
        )?;

        let amount_correctness_proof = single_property_prover(
            CorrectnessProverAwaitingChallenge {
                pub_key: sender_enc_keys.public,
                w: witness.clone(),
                pc_gens: &gens,
            },
            rng,
        )?;

        // Add the necessary payload for auditors.
        let auditors_payload = add_transaction_auditor(
            auditors_enc_pub_keys,
            &sender_enc_keys.public,
            &witness,
            rng,
        )?;

        Ok(InitializedTransferTx {
            amount_equal_cipher_proof,
            non_neg_amount_proof,
            enough_fund_proof,
            asset_id_equal_cipher_with_sender_receiver_keys_proof,
            balance_refreshed_same_proof,
            asset_id_refreshed_same_proof,
            asset_id_correctness_proof,
            amount_correctness_proof,
            memo: TransferTxMemo {
                sender_account_id: sender_pub_account.enc_asset_id,
                receiver_account_id: receiver_pub_account.enc_asset_id,
                enc_amount_using_sender: sender_new_enc_amount,
                enc_amount_using_receiver: receiver_new_enc_amount,
                refreshed_enc_balance,
                refreshed_enc_asset_id,
                enc_asset_id_using_receiver,
                enc_asset_id_for_mediator,
                enc_amount_for_mediator,
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
#[derive(Clone, Debug)]
pub struct CtxReceiver;

impl TransferTransactionReceiver for CtxReceiver {
    fn finalize_transaction<T: RngCore + CryptoRng>(
        &self,
        initialized_transaction: InitializedTransferTx,
        receiver_account: Account,
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<FinalizedTransferTx> {
        let receiver_enc_sec = &receiver_account.secret.enc_keys.secret;
        let receiver_pub_account = &receiver_account.public;

        // Check that the amount is correct.
        receiver_enc_sec
            .verify(
                &initialized_transaction.memo.enc_amount_using_receiver,
                &amount.into(),
            )
            .map_err(|_| ErrorKind::TransactionAmountMismatch {
                expected_amount: amount,
            })?;

        // Generate proof of equality of asset ids.
        let enc_asset_id_from_sender = initialized_transaction.memo.enc_asset_id_using_receiver;
        let enc_asset_id_from_receiver_acc = receiver_pub_account.enc_asset_id;
        let gens = PedersenGens::default();
        let prover = CipherTextRefreshmentProverAwaitingChallenge::new(
            receiver_enc_sec.clone(),
            enc_asset_id_from_receiver_acc,
            enc_asset_id_from_sender,
            &gens,
        );

        let proof = single_property_prover(prover, rng)?;

        Ok(FinalizedTransferTx {
            init_data: initialized_transaction,
            asset_id_from_sender_equal_to_receiver_proof: proof,
        })
    }
}

// ------------------------------------------------------------------------------------------------
// -                                           Mediator                                           -
// ------------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct CtxMediator;

impl TransferTransactionMediator for CtxMediator {
    fn justify_transaction<R: RngCore + CryptoRng>(
        &self,
        finalized_transaction: FinalizedTransferTx,
        mediator_enc_keys: &EncryptionKeys,
        sender_account: &PubAccount,
        sender_init_balance: &EncryptedAmount,
        receiver_account: &PubAccount,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
        asset_id_hint: AssetId,
        rng: &mut R,
    ) -> Fallible<JustifiedTransferTx> {
        // Verify receiver's part of the transaction.
        let _ = verify_finalized_transaction(&finalized_transaction, receiver_account)?;

        // Verify sender's part of the transaction.
        // This includes checking the auditors' payload.
        let init_tx_data = &finalized_transaction.init_data;
        let _ = verify_initialized_transaction(
            &init_tx_data,
            sender_account,
            sender_init_balance,
            receiver_account,
            auditors_enc_pub_keys,
            rng,
        )?;

        let gens = &PedersenGens::default();
        let tx_data = &init_tx_data;

        // Verify that the encrypted amount is correct.
        let amount = mediator_enc_keys
            .secret
            .const_time_decrypt(&tx_data.memo.enc_amount_for_mediator)?;
        single_property_verifier(
            &CorrectnessVerifier {
                value: amount.into(),
                pub_key: sender_account.owner_enc_pub_key,
                cipher: tx_data.memo.enc_amount_using_sender,
                pc_gens: &gens,
            },
            tx_data.amount_correctness_proof,
        )?;

        // Verify that the encrypted asset_id is correct.
        mediator_enc_keys.secret.verify(
            &tx_data.memo.enc_asset_id_for_mediator,
            &asset_id_hint.clone().into(),
        )?;

        let asset_id = asset_id_hint;
        single_property_verifier(
            &CorrectnessVerifier {
                value: asset_id.into(),
                pub_key: receiver_account.owner_enc_pub_key,
                cipher: tx_data.memo.enc_asset_id_using_receiver,
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
#[derive(Clone, Debug)]
pub struct TransactionValidator;

impl TransferTransactionVerifier for TransactionValidator {
    fn verify_transaction<R: RngCore + CryptoRng>(
        &self,
        justified_transaction: &JustifiedTransferTx,
        sender_account: &PubAccount,
        sender_init_balance: &EncryptedAmount,
        receiver_account: &PubAccount,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
        rng: &mut R,
    ) -> Fallible<()> {
        ensure!(
            sender_account.enc_asset_id
                == justified_transaction
                    .finalized_data
                    .init_data
                    .memo
                    .sender_account_id,
            ErrorKind::AccountIdMismatch
        );
        ensure!(
            receiver_account.enc_asset_id
                == justified_transaction
                    .finalized_data
                    .init_data
                    .memo
                    .receiver_account_id,
            ErrorKind::AccountIdMismatch
        );
        let finalized_transaction = &justified_transaction.finalized_data;
        let initialized_transaction = &finalized_transaction.init_data;
        verify_initialized_transaction(
            &initialized_transaction,
            sender_account,
            sender_init_balance,
            receiver_account,
            auditors_enc_pub_keys,
            rng,
        )?;

        verify_finalized_transaction(&finalized_transaction, receiver_account)?;

        Ok(())
    }
}

fn verify_initialized_transaction<R: RngCore + CryptoRng>(
    transaction: &InitializedTransferTx,
    sender_account: &PubAccount,
    sender_init_balance: &EncryptedAmount,
    receiver_account: &PubAccount,
    auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
    rng: &mut R,
) -> Fallible<TransferTxState> {
    verify_initial_transaction_proofs(
        transaction,
        sender_account,
        sender_init_balance,
        receiver_account,
        auditors_enc_pub_keys,
        rng,
    )?;

    Ok(TransferTxState::Initialization(TxSubstate::Validated))
}

fn verify_finalized_transaction(
    transaction_final_data: &FinalizedTransferTx,
    receiver_account: &PubAccount,
) -> Fallible<TransferTxState> {
    let memo = &transaction_final_data.init_data.memo;

    // In the initial transaction, the sender has encrypted the asset id
    // using the receiver pub key. We verify that this encrypted asset id
    // is the same as the one in the receiver account
    single_property_verifier(
        &CipherTextRefreshmentVerifier::new(
            receiver_account.owner_enc_pub_key,
            receiver_account.enc_asset_id,
            memo.enc_asset_id_using_receiver,
            &PedersenGens::default(),
        ),
        transaction_final_data.asset_id_from_sender_equal_to_receiver_proof,
    )?;

    Ok(TransferTxState::Finalization(TxSubstate::Validated))
}

fn verify_initial_transaction_proofs<R: RngCore + CryptoRng>(
    transaction: &InitializedTransferTx,
    sender_account: &PubAccount,
    sender_init_balance: &EncryptedAmount,
    receiver_account: &PubAccount,
    auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
    rng: &mut R,
) -> Fallible<()> {
    let memo = &transaction.memo;
    let init_data = &transaction;
    let gens = &PedersenGens::default();

    // Verify that the encrypted amounts are equal.
    single_property_verifier(
        &EncryptingSameValueVerifier {
            pub_key1: sender_account.owner_enc_pub_key,
            pub_key2: receiver_account.owner_enc_pub_key,
            cipher1: memo.enc_amount_using_sender,
            cipher2: memo.enc_amount_using_receiver,
            pc_gens: &gens,
        },
        init_data.amount_equal_cipher_proof,
    )?;

    // Verify that the amount is not negative.
    verify_within_range(&init_data.non_neg_amount_proof, rng)?;

    // verify that the balance refreshment was done correctly.
    single_property_verifier(
        &CipherTextRefreshmentVerifier::new(
            sender_account.owner_enc_pub_key,
            *sender_init_balance,
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
            sender_account.owner_enc_pub_key,
            sender_account.enc_asset_id,
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
            pub_key1: sender_account.owner_enc_pub_key,
            pub_key2: receiver_account.owner_enc_pub_key,
            cipher1: memo.refreshed_enc_asset_id,
            cipher2: memo.enc_asset_id_using_receiver,
            pc_gens: &gens,
        },
        init_data.asset_id_equal_cipher_with_sender_receiver_keys_proof,
    )?;

    // Verify that all auditors' payload is included, and
    // that the auditors' ciphertexts encrypt the same amount as sender's ciphertext.
    verify_auditor_payload(
        &init_data.auditors_payload,
        auditors_enc_pub_keys,
        sender_account.owner_enc_pub_key,
        init_data.memo.enc_amount_using_sender,
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
#[derive(Clone, Debug)]
pub struct CtxAuditor;

impl TransferTransactionAuditor for CtxAuditor {
    /// Verify the initialized, finalized, and justified transactions.
    /// Audit the sender's encrypted amount.
    fn audit_transaction(
        &self,
        justified_transaction: &JustifiedTransferTx,
        sender_account: &PubAccount,
        receiver_account: &PubAccount,
        auditor_enc_key: &(u32, EncryptionKeys),
    ) -> Fallible<()> {
        ensure!(
            sender_account.enc_asset_id
                == justified_transaction
                    .finalized_data
                    .init_data
                    .memo
                    .sender_account_id,
            ErrorKind::AccountIdMismatch
        );
        ensure!(
            receiver_account.enc_asset_id
                == justified_transaction
                    .finalized_data
                    .init_data
                    .memo
                    .receiver_account_id,
            ErrorKind::AccountIdMismatch
        );

        let gens = &PedersenGens::default();
        let finalized_transaction = &justified_transaction.finalized_data;
        let initialized_transaction = &finalized_transaction.init_data;

        verify_finalized_transaction(&finalized_transaction, &receiver_account)?;

        // If all checks pass, decrypt the encrypted amount and verify sender's correctness proof.
        let _: Fallible<()> = initialized_transaction
            .auditors_payload
            .iter()
            .map(|payload| {
                if payload.auditor_id == auditor_enc_key.0 {
                    let amount = auditor_enc_key
                        .1
                        .secret
                        .const_time_decrypt(&payload.encrypted_amount)?;

                    let result = single_property_verifier(
                        &CorrectnessVerifier {
                            value: amount.into(),
                            pub_key: sender_account.owner_enc_pub_key,
                            cipher: initialized_transaction.memo.enc_amount_using_sender,
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
        account::{deposit, withdraw},
        EncryptedAmount, EncryptedAmountWithHint, EncryptedAssetId, EncryptionKeys,
        EncryptionPubKey, SecAccount, TransferTxMemo,
    };
    use confidential_identity_core::{
        asset_proofs::{
            ciphertext_refreshment_proof::CipherEqualSamePubKeyProof,
            correctness_proof::CorrectnessProof,
            encrypting_same_value_proof::CipherEqualDifferentPubKeyProof,
            range_proof::InRangeProof, AssetId, ElgamalSecretKey,
        },
        curve25519_dalek::scalar::Scalar,
    };
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
            public: elg_pub,
            secret: elg_secret,
        }
    }

    fn mock_ctx_init_memo<R: RngCore + CryptoRng>(
        receiver_pub_key: EncryptionPubKey,
        amount: Balance,
        asset_id: AssetId,
        rng: &mut R,
    ) -> TransferTxMemo {
        let (_, enc_amount_using_receiver) = receiver_pub_key.encrypt_value(amount.into(), rng);
        let (_, enc_asset_id_using_receiver) = receiver_pub_key.encrypt_value(asset_id.into(), rng);
        TransferTxMemo {
            sender_account_id: EncryptedAssetId::default(),
            receiver_account_id: EncryptedAssetId::default(),
            enc_amount_using_sender: EncryptedAmount::default(),
            enc_amount_using_receiver,
            refreshed_enc_balance: EncryptedAmount::default(),
            refreshed_enc_asset_id: EncryptedAssetId::default(),
            enc_asset_id_using_receiver,
            enc_asset_id_for_mediator: EncryptedAssetId::default(),
            enc_amount_for_mediator: EncryptedAmountWithHint::default(),
        }
    }

    fn mock_gen_account<R: RngCore + CryptoRng>(
        receiver_enc_pub_key: EncryptionPubKey,
        asset_id: AssetId,
        balance: Balance,
        rng: &mut R,
    ) -> Fallible<(PubAccount, EncryptedAmount)> {
        let (_, enc_asset_id) = receiver_enc_pub_key.encrypt_value(asset_id.into(), rng);
        let (_, enc_balance) = receiver_enc_pub_key.encrypt_value(Scalar::from(balance), rng);

        Ok((
            PubAccount {
                enc_asset_id,
                owner_enc_pub_key: receiver_enc_pub_key,
            },
            enc_balance,
        ))
    }

    fn mock_ctx_init_data<R: RngCore + CryptoRng>(
        receiver_pub_key: EncryptionPubKey,
        expected_amount: Balance,
        asset_id: AssetId,
        rng: &mut R,
    ) -> InitializedTransferTx {
        InitializedTransferTx {
            memo: mock_ctx_init_memo(receiver_pub_key, expected_amount, asset_id, rng),
            asset_id_equal_cipher_with_sender_receiver_keys_proof:
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
        let ctx_receiver = CtxReceiver;
        let expected_amount = 10;
        let asset_id = AssetId::from(20u32);
        let balance = 0;
        let mut rng = StdRng::from_seed([17u8; 32]);

        let receiver_enc_keys = mock_gen_enc_key_pair(17u8);

        let ctx_init_data = mock_ctx_init_data(
            receiver_enc_keys.public,
            expected_amount,
            asset_id.clone(),
            &mut rng,
        );
        let (pub_account, _enc_balance) = mock_gen_account(
            receiver_enc_keys.public,
            asset_id.clone(),
            balance,
            &mut rng,
        )
        .unwrap();
        let receiver_account = Account {
            public: pub_account,
            secret: SecAccount {
                enc_keys: receiver_enc_keys,
                asset_id_witness: CommitmentWitness::from((asset_id.into(), &mut rng)),
            },
        };

        let result = ctx_receiver.finalize_transaction(
            ctx_init_data,
            receiver_account,
            expected_amount,
            &mut rng,
        );

        result.unwrap();
        // Correctness of the proof will be verified in the verify function
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_amount_mismatch_error() {
        let ctx_receiver = CtxReceiver;
        let expected_amount = 10;
        let received_amount = 20;
        let asset_id = AssetId::from(20);
        let balance = 0;
        let mut rng = StdRng::from_seed([17u8; 32]);

        let receiver_enc_keys = mock_gen_enc_key_pair(17u8);

        let ctx_init_data = mock_ctx_init_data(
            receiver_enc_keys.public,
            received_amount,
            asset_id.clone(),
            &mut rng,
        );
        let receiver_account = Account {
            public: mock_gen_account(
                receiver_enc_keys.public,
                asset_id.clone(),
                balance,
                &mut rng,
            )
            .unwrap()
            .0,
            secret: SecAccount {
                enc_keys: receiver_enc_keys,
                asset_id_witness: CommitmentWitness::from((asset_id.into(), &mut rng)),
            },
        };

        let result = ctx_receiver.finalize_transaction(
            ctx_init_data,
            receiver_account,
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
        let sender = CtxSender;
        let receiver = CtxReceiver;
        let mediator = CtxMediator;
        let tx_validator = TransactionValidator;
        let asset_id = AssetId::from(20);
        let sender_balance = 40;
        let receiver_balance = 0;
        let amount = 30;

        let mut rng = StdRng::from_seed([17u8; 32]);

        let sender_enc_keys = mock_gen_enc_key_pair(10u8);

        let receiver_enc_keys = mock_gen_enc_key_pair(12u8);

        let mediator_enc_keys = mock_gen_enc_key_pair(14u8);

        let (receiver_pub_account, receiver_init_balance) = mock_gen_account(
            receiver_enc_keys.public,
            asset_id.clone(),
            receiver_balance,
            &mut rng,
        )
        .unwrap();
        let receiver_account = Account {
            public: receiver_pub_account,
            secret: SecAccount {
                enc_keys: receiver_enc_keys.clone(),
                asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
            },
        };

        let (sender_pub_account, sender_init_balance) = mock_gen_account(
            sender_enc_keys.public,
            asset_id.clone(),
            sender_balance,
            &mut rng,
        )
        .unwrap();
        let sender_account = Account {
            public: sender_pub_account,
            secret: SecAccount {
                enc_keys: sender_enc_keys.clone(),
                asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
            },
        };

        // Create the transaction and check its result and state
        let result = sender.create_transaction(
            &sender_account,
            &sender_init_balance,
            &receiver_account.public,
            &mediator_enc_keys.public,
            &[],
            amount,
            &mut rng,
        );
        let ctx_init_data = result.unwrap();

        // Finalize the transaction and check its state.
        let result = receiver.finalize_transaction(
            ctx_init_data,
            receiver_account.clone(),
            amount,
            &mut rng,
        );
        let ctx_finalized_data = result.unwrap();

        // Justify the transaction
        let result = mediator.justify_transaction(
            ctx_finalized_data,
            &mediator_enc_keys,
            &sender_account.public,
            &sender_init_balance,
            &receiver_account.public,
            &[],
            asset_id,
            &mut rng,
        );
        let justified_finalized_ctx_data = result.unwrap();

        assert!(tx_validator
            .verify_transaction(
                &justified_finalized_ctx_data,
                &sender_account.public,
                &sender_init_balance,
                &receiver_account.public,
                &[],
                &mut rng,
            )
            .is_ok());

        // ----------------------- Processing
        // Check that the transferred amount is added to the receiver's account balance
        // and subtracted from sender's balance.
        let updated_sender_balance = withdraw(
            &sender_init_balance,
            &justified_finalized_ctx_data
                .finalized_data
                .init_data
                .memo
                .enc_amount_using_sender,
        );
        let updated_receiver_balance = deposit(
            &receiver_init_balance,
            &justified_finalized_ctx_data
                .finalized_data
                .init_data
                .memo
                .enc_amount_using_receiver,
        );

        assert!(sender_enc_keys
            .secret
            .verify(&updated_sender_balance, &(sender_balance - amount).into())
            .is_ok());
        assert!(receiver_enc_keys
            .secret
            .verify(
                &updated_receiver_balance,
                &(receiver_balance + amount).into()
            )
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
            mock_gen_account(enc_keys.public, asset_id.clone(), balance, &mut rng).unwrap();

        (
            Account {
                public: pub_account,
                secret: SecAccount {
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
        let sender = CtxSender;
        let receiver = CtxReceiver;
        let mediator = CtxMediator;
        let validator = TransactionValidator;
        let asset_id = AssetId::from(20);
        let sender_balance = 500;
        let receiver_balance = 0;
        let amount = 400;

        let mut rng = StdRng::from_seed([19u8; 32]);

        let mediator_enc_keys = mock_gen_enc_key_pair(140u8);

        let (receiver_account, receiver_init_balance) =
            account_create_helper([18u8; 32], 120u8, receiver_balance, asset_id.clone());

        let (sender_account, sender_init_balance) =
            account_create_helper([17u8; 32], 100u8, sender_balance, asset_id.clone());

        // Create the transaction and check its result and state
        let ctx_init = sender
            .create_transaction(
                &sender_account,
                &sender_init_balance,
                &receiver_account.public,
                &mediator_enc_keys.public,
                sender_auditor_list,
                amount,
                &mut rng,
            )
            .unwrap();

        // Finalize the transaction and check its state
        let ctx_final = receiver
            .finalize_transaction(ctx_init, receiver_account.clone(), amount, &mut rng)
            .unwrap();

        // Justify the transaction
        let result = mediator.justify_transaction(
            ctx_final,
            &mediator_enc_keys,
            &sender_account.public,
            &sender_init_balance,
            &receiver_account.public,
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
            &sender_account.public,
            &sender_init_balance,
            &receiver_account.public,
            validator_auditor_list,
            &mut rng,
        );

        if validator_check_fails {
            assert_err!(result, ErrorKind::AuditorPayloadError);
            return;
        }

        assert!(result.is_ok());

        // ----------------------- Processing
        // Check that the transferred amount is added to the receiver's account balance
        // and subtracted from sender's balance.
        let updated_sender_balance = withdraw(
            &sender_init_balance,
            &ctx_just
                .finalized_data
                .init_data
                .memo
                .enc_amount_using_sender,
        );
        let updated_receiver_balance = deposit(
            &receiver_init_balance,
            &ctx_just
                .finalized_data
                .init_data
                .memo
                .enc_amount_using_receiver,
        );

        assert!(sender_account
            .secret
            .enc_keys
            .secret
            .verify(&updated_sender_balance, &(sender_balance - amount).into())
            .is_ok());
        assert!(receiver_account
            .secret
            .enc_keys
            .secret
            .verify(
                &updated_receiver_balance,
                &(receiver_balance + amount).into()
            )
            .is_ok());

        // ----------------------- Auditing
        let _ = auditors_list.iter().map(|auditor| {
            let transaction_auditor = CtxAuditor;
            assert!(transaction_auditor
                .audit_transaction(
                    &ctx_just,
                    &sender_account.public,
                    &receiver_account.public,
                    auditor,
                )
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
            .map(|a| (a.0, a.1.public))
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
