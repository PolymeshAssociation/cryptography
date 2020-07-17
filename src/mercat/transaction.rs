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
        Account, AuditorPayload, EncryptedAmount, EncryptionKeys, EncryptionPubKey, FinalizedTx,
        FinalizedTxContent, InitializedTx, InititializedTxContent, JustifiedTx, PubAccount,
        SigningKeys, SigningPubKey, TransactionAuditor, TransactionMediator, TransactionReceiver,
        TransactionSender, TransactionVerifier, TxMemo, TxState, TxSubstate,
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

impl TransactionSender for CtxSender {
    fn create_transaction<T: RngCore + CryptoRng>(
        &self,
        sndr_account: &Account,
        rcvr_pub_account: &PubAccount,
        mdtr_pub_key: &EncryptionPubKey,
        auditors_enc_pub_keys: &Option<Vec<(u32, EncryptionPubKey)>>,
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<InitializedTx> {
        let gens = PedersenGens::default();
        // NOTE: If this decryption ends up being too slow, we can pass in the balance
        // as input.
        let sndr_enc_keys = &sndr_account.scrt.enc_keys;
        let sndr_sign_keys = &sndr_account.scrt.sign_keys;
        let asset_id = sndr_account.scrt.asset_id_witness.value();
        let sndr_pub_account = &sndr_account.pblc.content;
        let rcvr_pub_account = &rcvr_pub_account.content;
        let rcvr_pub_key = rcvr_pub_account.memo.owner_enc_pub_key;

        let balance = sndr_enc_keys.scrt.decrypt(&sndr_pub_account.enc_balance)?;
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

        let non_neg_amount_proof = InRangeProof::from(prove_within_range(
            amount.into(),
            amount_enc_blinding,
            BALANCE_RANGE,
            rng,
        )?);

        // Prove that the amount encrypted under different public keys are the same.
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
        // correctly.
        let balance_refresh_enc_blinding = Scalar::random(rng);
        let refreshed_enc_balance = sndr_pub_account
            .enc_balance
            .refresh(&sndr_enc_keys.scrt, balance_refresh_enc_blinding)?;

        let balance_refreshed_same_proof = single_property_prover(
            CipherTextRefreshmentProverAwaitingChallenge::new(
                sndr_enc_keys.scrt.clone(),
                sndr_pub_account.enc_balance,
                refreshed_enc_balance,
                &gens,
            ),
            rng,
        )?;

        // Prove that the sender has enough funds.
        let blinding = balance_refresh_enc_blinding - amount_enc_blinding;
        let enough_fund_proof = InRangeProof::from(prove_within_range(
            (balance - amount).into(),
            blinding,
            BALANCE_RANGE,
            rng,
        )?);

        // Refresh the encrypted asset id of the sender account and prove that the
        // refreshment was done correctly.
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

        // Prove the new refreshed encrytped asset id is the same as the one
        // encrypted by the receiver's pub key.
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

        // Prepare the correctness proofs for the mediator.
        let asset_id_witness_blinding_for_mdtr = Scalar::random(rng);
        let asset_id_witness_for_mdtr =
            CommitmentWitness::new(asset_id.into(), asset_id_witness_blinding_for_mdtr);
        let enc_asset_id_for_mdtr = mdtr_pub_key.encrypt(&asset_id_witness_for_mdtr);

        let amount_witness_blinding_for_mdtr = Scalar::random(rng);
        let amount_witness_for_mdtr =
            CommitmentWitness::new(amount.into(), amount_witness_blinding_for_mdtr);
        let enc_amount_for_mdtr = mdtr_pub_key.encrypt(&amount_witness_for_mdtr);

        // todo shouldn't this be made to receiver's public key?
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
                pub_key: sndr_enc_keys.pblc.clone(),
                w: witness.clone(),
                pc_gens: &gens,
            },
            rng,
        )?);

        // Add the necessary payload for auditors.
        let auditors_payload =
            add_transaction_auditor(auditors_enc_pub_keys, &sndr_enc_keys.pblc, &witness, rng)?;

        // Gather the content and sign it.
        let content = InititializedTxContent {
            amount_equal_cipher_proof,
            non_neg_amount_proof,
            enough_fund_proof,
            asset_id_equal_cipher_with_sndr_rcvr_keys_proof,
            balance_refreshed_same_proof,
            asset_id_refreshed_same_proof,
            asset_id_correctness_proof,
            amount_correctness_proof,
            memo: TxMemo {
                sndr_account_id: sndr_pub_account.id,
                rcvr_account_id: rcvr_pub_account.id,
                enc_amount_using_sndr: sndr_new_enc_amount.into(),
                enc_amount_using_rcvr: rcvr_new_enc_amount.into(),
                refreshed_enc_balance: refreshed_enc_balance.into(),
                refreshed_enc_asset_id: refreshed_enc_asset_id.into(),
                enc_asset_id_using_rcvr: enc_asset_id_using_rcvr.into(),
                enc_asset_id_for_mdtr: enc_asset_id_for_mdtr.into(),
                enc_amount_for_mdtr: enc_amount_for_mdtr.into(),
            },
            auditors_payload: auditors_payload,
        };

        let message = content.encode();
        let sig = sndr_sign_keys.sign(SIG_CTXT.bytes(&message));

        Ok(InitializedTx { content, sig })
    }
}

fn add_transaction_auditor<T: RngCore + CryptoRng>(
    auditors_enc_pub_keys: &Option<Vec<(u32, EncryptionPubKey)>>,
    sender_enc_pub_key: &EncryptionPubKey,
    amount_witness: &CommitmentWitness,
    rng: &mut T,
) -> Fallible<Option<Vec<AuditorPayload>>> {
    let gens = PedersenGens::default();

    // Add the required payload for the auditors.
    if let Some(auditors_enc_pub_keys) = auditors_enc_pub_keys {
        let mut payload_vec: Vec<AuditorPayload> = Vec::with_capacity(auditors_enc_pub_keys.len());
        for (auditor_id, auditor_enc_pub_key) in auditors_enc_pub_keys.iter() {
            let encrypted_amount = auditor_enc_pub_key.encrypt(amount_witness);

            // Prove that the sender and auditor's ciphertexts are encrypting the same
            // commitment witness.
            let amount_equal_cipher_proof =
                CipherEqualDifferentPubKeyProof::from(single_property_prover(
                    EncryptingSameValueProverAwaitingChallenge {
                        pub_key1: sender_enc_pub_key.clone(),
                        pub_key2: auditor_enc_pub_key.clone(),
                        w: Zeroizing::new(amount_witness.clone()),
                        pc_gens: &gens,
                    },
                    rng,
                )?);

            let payload = AuditorPayload {
                auditor_id: auditor_id.clone(),
                encrypted_amount,
                amount_equal_cipher_proof,
            };

            payload_vec.push(payload);
        }

        Ok(Some(payload_vec))
    } else {
        Ok(None)
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

impl TransactionReceiver for CtxReceiver {
    fn finalize_transaction<T: RngCore + CryptoRng>(
        &self,
        initialized_transaction: InitializedTx,
        sndr_sign_pub_key: &SigningPubKey,
        rcvr_account: Account,
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<FinalizedTx> {
        // Verify sender's signature.
        let ctx_data = &initialized_transaction;
        let message = ctx_data.content.encode();
        let _ = sndr_sign_pub_key.verify(SIG_CTXT.bytes(&message), &ctx_data.sig)?;

        self.finalize_by_receiver(initialized_transaction, rcvr_account, amount, rng)
    }
}

impl CtxReceiver {
    /// This function is called by the receiver of the transaction to finalize the
    /// transaction. It corresponds to `FinalizeCTX` function of the MERCAT paper.
    fn finalize_by_receiver<T: RngCore + CryptoRng>(
        &self,
        transaction_init_data: InitializedTx,
        rcvr_account: Account,
        expected_amount: Balance,
        rng: &mut T,
    ) -> Fallible<FinalizedTx> {
        let rcvr_enc_sec = &rcvr_account.scrt.enc_keys.scrt;
        let rcvr_sign_keys = &rcvr_account.scrt.sign_keys;
        let rcvr_pub_account = &rcvr_account.pblc.content;

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

        // Gather the content and sign it
        let content = FinalizedTxContent {
            init_data: transaction_init_data,
            asset_id_from_sndr_equal_to_rcvr_proof: proof,
        };

        let message = content.encode();
        let sig = rcvr_sign_keys.sign(SIG_CTXT.bytes(&message));

        Ok(FinalizedTx { content, sig })
    }
}
// ------------------------------------------------------------------------------------------------
// -                                           Mediator                                           -
// ------------------------------------------------------------------------------------------------
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct CtxMediator {}

impl TransactionMediator for CtxMediator {
    fn justify_transaction<R: RngCore + CryptoRng>(
        &self,
        finalized_transaction: FinalizedTx,
        mdtr_enc_keys: &EncryptionKeys,
        mdtr_sign_keys: &SigningKeys,
        sndr_account: &PubAccount,
        rcvr_account: &PubAccount,
        auditors_enc_pub_keys: &Option<Vec<(u32, EncryptionPubKey)>>,
        asset_id_hint: AssetId,
        rng: &mut R,
    ) -> Fallible<JustifiedTx> {
        // Verify receiver's part of the transaction.
        let _ = verify_finalized_transaction(&finalized_transaction, rcvr_account)?;

        // Verify sender's part of the transaction.
        // This includes checking the auditors' payload.
        let init_tx_data = &finalized_transaction.content.init_data;
        let _ = verify_initialized_transaction(
            &init_tx_data,
            sndr_account,
            rcvr_account,
            auditors_enc_pub_keys,
            rng,
        )?;

        let gens = &PedersenGens::default();
        let tx_data = &init_tx_data.content;

        // Verify that the encrypted amount is correct.
        let amount = mdtr_enc_keys
            .scrt
            .decrypt(&tx_data.memo.enc_amount_for_mdtr)?;
        single_property_verifier(
            &CorrectnessVerifier {
                value: amount.into(),
                pub_key: sndr_account.content.memo.owner_enc_pub_key,
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
                pub_key: mdtr_enc_keys.pblc,
                cipher: tx_data.memo.enc_asset_id_for_mdtr,
                pc_gens: &gens,
            },
            tx_data.asset_id_correctness_proof,
        )?;

        let message = finalized_transaction.encode();
        let sig = mdtr_sign_keys.sign(SIG_CTXT.bytes(&message));

        Ok(JustifiedTx {
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

impl TransactionVerifier for TransactionValidator {
    fn verify_transaction<R: RngCore + CryptoRng>(
        &self,
        justified_transaction: &JustifiedTx,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        mdtr_sign_pub_key: &SigningPubKey,
        auditors_enc_pub_keys: &Option<Vec<(u32, EncryptionPubKey)>>,
        rng: &mut R,
    ) -> Fallible<(PubAccount, PubAccount)> {
        ensure!(
            sndr_account.content.id
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
            rcvr_account.content.id
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
            auditors_enc_pub_keys,
            rng,
        )?;

        verify_finalized_transaction(&finalized_transaction, &rcvr_account)?;
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
    transaction: &InitializedTx,
    sndr_account: &PubAccount,
    rcvr_account: &PubAccount,
    auditors_enc_pub_keys: &Option<Vec<(u32, EncryptionPubKey)>>,
    rng: &mut R,
) -> Fallible<TxState> {
    let message = transaction.content.encode();
    let _ = sndr_account
        .content
        .memo
        .owner_sign_pub_key
        .verify(SIG_CTXT.bytes(&message), &transaction.sig)?;

    verify_initital_transaction_proofs(
        transaction,
        sndr_account,
        rcvr_account,
        auditors_enc_pub_keys,
        rng,
    )?;

    Ok(TxState::Initialization(TxSubstate::Validated))
}

fn verify_finalized_transaction(
    transaction_final_data: &FinalizedTx,
    rcvr_account: &PubAccount,
) -> Fallible<TxState> {
    let message = transaction_final_data.content.encode();
    let _ = rcvr_account
        .content
        .memo
        .owner_sign_pub_key
        .verify(SIG_CTXT.bytes(&message), &transaction_final_data.sig)?;

    let memo = &transaction_final_data.content.init_data.content.memo;
    let final_content = &transaction_final_data.content;

    // In the inital transaction, the sender has encrypted the asset id
    // using the receiver pub key. We verify that this encrypted asset id
    // is the same as the one in the receiver account
    single_property_verifier(
        &CipherTextRefreshmentVerifier::new(
            rcvr_account.content.memo.owner_enc_pub_key,
            rcvr_account.content.enc_asset_id,
            memo.enc_asset_id_using_rcvr,
            &PedersenGens::default(),
        ),
        final_content.asset_id_from_sndr_equal_to_rcvr_proof,
    )?;

    Ok(TxState::Finalization(TxSubstate::Validated))
}

fn verify_justified_transaction(
    transaction_justified_final_data: &JustifiedTx,
    mdtr_sign_pub_key: &SigningPubKey,
) -> Fallible<TxState> {
    let ctx_data = &transaction_justified_final_data;
    let message = ctx_data.content.encode();
    let _ = mdtr_sign_pub_key.verify(SIG_CTXT.bytes(&message), &ctx_data.sig)?;

    Ok(TxState::Justification(TxSubstate::Validated))
}

fn verify_initital_transaction_proofs<R: RngCore + CryptoRng>(
    transaction: &InitializedTx,
    sndr_account: &PubAccount,
    rcvr_account: &PubAccount,
    auditors_enc_pub_keys: &Option<Vec<(u32, EncryptionPubKey)>>,
    rng: &mut R,
) -> Fallible<()> {
    let memo = &transaction.content.memo;
    let init_data = &transaction.content;
    let sndr_account = &sndr_account.content;
    let gens = &PedersenGens::default();

    // Verify that the encrypted amounts are equal.
    single_property_verifier(
        &EncryptingSameValueVerifier {
            pub_key1: sndr_account.memo.owner_enc_pub_key,
            pub_key2: rcvr_account.content.memo.owner_enc_pub_key,
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
            sndr_account.memo.owner_enc_pub_key,
            sndr_account.enc_balance,
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
            sndr_account.memo.owner_enc_pub_key,
            sndr_account.enc_asset_id,
            memo.refreshed_enc_asset_id,
            &gens,
        ),
        init_data.asset_id_refreshed_same_proof,
    )?;

    // In the inital transaction, the sender has encrypted the asset id
    // using the receiver pub key. We verify that this encrypted asset id
    // is the same as the one in the sender account.
    single_property_verifier(
        &EncryptingSameValueVerifier {
            pub_key1: sndr_account.memo.owner_enc_pub_key,
            pub_key2: rcvr_account.content.memo.owner_enc_pub_key,
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
        sndr_account.memo.owner_enc_pub_key.clone(),
        init_data.memo.enc_amount_using_sndr.clone(),
    )?;

    Ok(())
}

fn verify_auditor_payload(
    auditors_payload: &Option<Vec<AuditorPayload>>,
    auditors_enc_pub_keys: &Option<Vec<(u32, EncryptionPubKey)>>,
    sender_enc_pub_key: EncryptionPubKey,
    sender_enc_amount: EncryptedAmount,
) -> Fallible<()> {
    let gens = &PedersenGens::default();
    ensure!(
        !(auditors_payload.is_none() ^ auditors_enc_pub_keys.is_none()),
        ErrorKind::AuditorPayloadError
    );

    if let Some(auditors) = auditors_enc_pub_keys {
        match auditors_payload {
            Some(auditor_payload) => {
                for (auditor_id, auditor_pub_key) in auditors {
                    let mut found_auditor = false;
                    for payload in auditor_payload.iter() {
                        if *auditor_id == payload.auditor_id {
                            // Verify that the encrypted amounts are equal.
                            single_property_verifier(
                                &EncryptingSameValueVerifier {
                                    pub_key1: sender_enc_pub_key,
                                    pub_key2: auditor_pub_key.clone(),
                                    cipher1: sender_enc_amount,
                                    cipher2: payload.encrypted_amount,
                                    pc_gens: &gens,
                                },
                                payload.amount_equal_cipher_proof,
                            )?;
                            found_auditor = true;
                            break;
                        }
                    }
                    ensure!(found_auditor, ErrorKind::AuditorPayloadError);
                }
            }
            None => return Err(ErrorKind::AuditorPayloadError.into()),
        }
    };

    Ok(())
}

// ------------------------------------------------------------------------------------------------
// -                                          Auditor                                           -
// ------------------------------------------------------------------------------------------------

/// Transaction Validator.
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct CtxAuditor {}

impl TransactionAuditor for CtxAuditor {
    /// Verify the intialized, finalized, and justified transactions.
    /// Audit the sender's encrypted amount.
    fn audit_transaction(
        &self,
        justified_transaction: &JustifiedTx,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        mdtr_sign_pub_key: &SigningPubKey,
        auditor_enc_key: &(u32, EncryptionKeys),
    ) -> Fallible<()> {
        ensure!(
            sndr_account.content.id
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
            rcvr_account.content.id
                == justified_transaction
                    .content
                    .content // finalized transaction data
                    .init_data
                    .content
                    .memo
                    .rcvr_account_id,
            ErrorKind::AccountIdMismatch
        );

        let gens = &PedersenGens::default();
        let finalized_transaction = &justified_transaction.content;
        let initialized_transaction = &finalized_transaction.content;

        // Checks sender's signature on the transaction.
        let message = initialized_transaction.init_data.content.encode();
        let _ = sndr_account.content.memo.owner_sign_pub_key.verify(
            SIG_CTXT.bytes(&message),
            &initialized_transaction.init_data.sig,
        )?;

        verify_finalized_transaction(&finalized_transaction, &rcvr_account)?;
        verify_justified_transaction(&justified_transaction, mdtr_sign_pub_key)?;

        // If all checks pass, decrypt the encrypted amount and verify sender's correctness proof.
        match &initialized_transaction.init_data.content.auditors_payload {
            Some(p) => {
                for payload in p.iter() {
                    if payload.auditor_id == auditor_enc_key.0 {
                        let amount = auditor_enc_key.1.scrt.decrypt(&payload.encrypted_amount)?;

                        single_property_verifier(
                            &CorrectnessVerifier {
                                value: amount.into(),
                                pub_key: sndr_account.content.memo.owner_enc_pub_key,
                                cipher: initialized_transaction
                                    .init_data
                                    .content
                                    .memo
                                    .enc_amount_using_sndr,
                                pc_gens: &gens,
                            },
                            initialized_transaction
                                .init_data
                                .content
                                .amount_correctness_proof,
                        )?;

                        return Ok(());
                    }
                }
            }
            None => return Err(ErrorKind::AuditorPayloadError.into()),
        }

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
            correctness_proof::CorrectnessProof, membership_proof::MembershipProof,
            wellformedness_proof::WellformednessProof, ElgamalSecretKey,
        },
        mercat::{
            AccountMemo, EncryptedAmount, EncryptedAssetId, EncryptionKeys, EncryptionPubKey,
            PubAccountContent, SecAccount, Signature, SigningKeys, SigningPubKey, TxMemo,
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
    ) -> TxMemo {
        let (_, enc_amount_using_rcvr) = rcvr_pub_key.encrypt_value(amount.into(), rng);
        let (_, enc_asset_id_using_rcvr) = rcvr_pub_key.encrypt_value(asset_id.into(), rng);
        TxMemo {
            sndr_account_id: 0,
            rcvr_account_id: 0,
            enc_amount_using_sndr: EncryptedAmount::default(),
            enc_amount_using_rcvr: EncryptedAmount::from(enc_amount_using_rcvr),
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
    ) -> InitializedTx {
        InitializedTx {
            content: InititializedTxContent {
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
                auditors_payload: None,
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

        let result =
            ctx_rcvr.finalize_by_receiver(ctx_init_data, rcvr_account, expected_amount, &mut rng);

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

        let result =
            ctx_rcvr.finalize_by_receiver(ctx_init_data, rcvr_account, expected_amount, &mut rng);

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

        // Create the trasaction and check its result and state
        let result = sndr.create_transaction(
            &sndr_account,
            &rcvr_account.pblc,
            &mdtr_enc_keys.pblc,
            &None,
            amount,
            &mut rng,
        );
        let ctx_init_data = result.unwrap();

        // Finalize the transaction and check its state
        let result =
            rcvr.finalize_by_receiver(ctx_init_data, rcvr_account.clone(), amount, &mut rng);
        let ctx_finalized_data = result.unwrap();

        // Justify the transaction
        let result = mdtr.justify_transaction(
            ctx_finalized_data,
            &mdtr_enc_keys,
            &mdtr_sign_keys,
            &sndr_account.pblc.clone(),
            &rcvr_account.pblc.clone(),
            &None,
            asset_id,
            &mut rng,
        );
        let justified_finalized_ctx_data = result.unwrap();

        let (updated_sender_account, updated_receiver_account) = tx_validator
            .verify_transaction(
                &justified_finalized_ctx_data,
                sndr_account.pblc,
                rcvr_account.pblc,
                &mdtr_sign_keys.public,
                &None,
                &mut rng,
            )
            .unwrap();

        // ----------------------- Processing
        // Check that the transferred amount is added to the receiver's account balance
        // and subtracted from sender's balance.
        assert!(sndr_enc_keys
            .scrt
            .verify(
                &updated_sender_account.content.enc_balance,
                &Scalar::from(sndr_balance - amount)
            )
            .is_ok());
        assert!(rcvr_enc_keys
            .scrt
            .verify(
                &updated_receiver_account.content.enc_balance,
                &Scalar::from(rcvr_balance + amount)
            )
            .is_ok());
    }

    // ------------------------------ Test Auditing Logic
    fn account_create_helper(
        seed0: [u8; 32],
        seed1: u8,
        seed2: u8,
        balance: Balance,
        asset_id: AssetId,
    ) -> Account {
        let mut rng = StdRng::from_seed(seed0);

        let enc_keys = mock_gen_enc_key_pair(seed1);
        let sign_keys = mock_gen_sign_key_pair(seed2);

        Account {
            pblc: mock_gen_account(
                enc_keys.pblc,
                sign_keys.public.clone(),
                asset_id.clone(),
                balance,
                &mut rng,
            )
            .unwrap(),
            scrt: SecAccount {
                enc_keys: enc_keys,
                sign_keys: sign_keys,
                asset_id_witness: CommitmentWitness::from((asset_id.into(), &mut rng)),
            },
        }
    }

    fn test_transaction_auditor_helper(
        sender_auditor_list: &Option<Vec<(u32, EncryptionPubKey)>>,
        mediator_auditor_list: &Option<Vec<(u32, EncryptionPubKey)>>,
        mediator_check_fails: bool,
        validator_auditor_list: &Option<Vec<(u32, EncryptionPubKey)>>,
        validator_check_fails: bool,
        auditors_list: &Option<Vec<(u32, EncryptionKeys)>>,
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
        let mdtr_sign_keys = mock_gen_sign_key_pair(150u8);

        let rcvr_account =
            account_create_helper([18u8; 32], 120u8, 130u8, rcvr_balance, asset_id.clone());

        let sndr_account =
            account_create_helper([17u8; 32], 100u8, 110u8, sndr_balance, asset_id.clone());

        // Create the trasaction and check its result and state
        let ctx_init = sndr
            .create_transaction(
                &sndr_account,
                &rcvr_account.pblc,
                &mdtr_enc_keys.pblc,
                sender_auditor_list,
                amount,
                &mut rng,
            )
            .unwrap();

        // Finalize the transaction and check its state
        let ctx_final = rcvr
            .finalize_transaction(
                ctx_init,
                &sndr_account.pblc.content.memo.owner_sign_pub_key.clone(),
                rcvr_account.clone(),
                amount,
                &mut rng,
            )
            .unwrap();

        // Justify the transaction
        let result = mdtr.justify_transaction(
            ctx_final,
            &mdtr_enc_keys,
            &mdtr_sign_keys,
            &sndr_account.pblc.clone(),
            &rcvr_account.pblc.clone(),
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
            sndr_account.pblc.clone(),
            rcvr_account.pblc.clone(),
            &mdtr_sign_keys.public,
            validator_auditor_list,
            &mut rng,
        );

        if validator_check_fails {
            assert_err!(result, ErrorKind::AuditorPayloadError);
            return;
        }

        let (updated_sender_account, updated_receiver_account) = result.unwrap();

        // ----------------------- Processing
        // Check that the transferred amount is added to the receiver's account balance
        // and subtracted from sender's balance.
        assert!(sndr_account
            .scrt
            .enc_keys
            .scrt
            .verify(
                &updated_sender_account.content.enc_balance,
                &Scalar::from(sndr_balance - amount)
            )
            .is_ok());
        assert!(rcvr_account
            .scrt
            .enc_keys
            .scrt
            .verify(
                &updated_receiver_account.content.enc_balance,
                &Scalar::from(rcvr_balance + amount)
            )
            .is_ok());

        // ----------------------- Auditing
        if let Some(auditors) = auditors_list {
            let _ = auditors.iter().map(|auditor| {
                let transaction_auditor = CtxAuditor {};
                assert!(transaction_auditor
                    .audit_transaction(
                        &ctx_just,
                        sndr_account.pblc.clone(),
                        rcvr_account.pblc.clone(),
                        &mdtr_sign_keys.public,
                        auditor,
                    )
                    .is_ok());
            });
        }
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_transaction_auditor() {
        // Make imaginary auditors.
        let auditors_num = 5u32;
        let auditors_secert_vec: Vec<(u32, EncryptionKeys)> = (0..auditors_num)
            .map(|index| {
                let auditor_keys = mock_gen_enc_key_pair(index as u8);
                (index, auditor_keys)
            })
            .collect();
        let auditors_secert_vec_option = Some(auditors_secert_vec.clone());

        let auditors_vec: Vec<(u32, EncryptionPubKey)> = auditors_secert_vec
            .iter()
            .map(|a| (a.0, a.1.pblc))
            .collect();

        let auditors_vec_option = Some(auditors_vec.clone());

        // Positive tests.

        // Include `auditors_num` auditors.
        test_transaction_auditor_helper(
            &auditors_vec_option,
            &auditors_vec_option,
            false,
            &auditors_vec_option,
            false,
            &auditors_secert_vec_option,
        );

        // Change the order of auditors lists on the mediator and validator sides.
        // The tests still must pass.
        let mediator_auditor_list = Some(vec![
            auditors_vec[1].clone(),
            auditors_vec[0].clone(),
            auditors_vec[3].clone(),
            auditors_vec[2].clone(),
            auditors_vec[4].clone(),
        ]);
        let validator_auditor_list = Some(vec![
            auditors_vec[4].clone(),
            auditors_vec[3].clone(),
            auditors_vec[2].clone(),
            auditors_vec[1].clone(),
            auditors_vec[0].clone(),
        ]);
        test_transaction_auditor_helper(
            &auditors_vec_option,
            &mediator_auditor_list,
            false,
            &validator_auditor_list,
            false,
            &auditors_secert_vec_option,
        );

        // Asset doesn't have any auditors.
        test_transaction_auditor_helper(&None, &None, false, &None, false, &None);

        // Negative tests.

        // Sender misses an auditor. Mediator catches it.
        let four_auditor_list = Some(vec![
            auditors_vec[1].clone(),
            auditors_vec[0].clone(),
            auditors_vec[3].clone(),
            auditors_vec[2].clone(),
        ]);
        test_transaction_auditor_helper(
            &four_auditor_list,
            &mediator_auditor_list,
            true,
            &validator_auditor_list,
            true,
            &auditors_secert_vec_option,
        );

        // Sender and mediator miss an auditor, but validator catches them.
        test_transaction_auditor_helper(
            &four_auditor_list,
            &four_auditor_list,
            false,
            &validator_auditor_list,
            true,
            &auditors_secert_vec_option,
        );

        // Sender doesn't include any auditors. Mediator catches it.
        test_transaction_auditor_helper(
            &None,
            &mediator_auditor_list,
            true,
            &validator_auditor_list,
            true,
            &auditors_secert_vec_option,
        );

        // Sender and mediator don't believe in auditors but validator does.
        test_transaction_auditor_helper(
            &None,
            &None,
            false,
            &validator_auditor_list,
            true,
            &auditors_secert_vec_option,
        );
    }
}
