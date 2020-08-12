//! The MERCAT's asset issuance implementation.

use crate::{
    asset_proofs::{
        correctness_proof::{CorrectnessProverAwaitingChallenge, CorrectnessVerifier},
        encrypting_same_value_proof::{
            EncryptingSameValueProverAwaitingChallenge, EncryptingSameValueVerifier,
        },
        encryption_proofs::single_property_prover,
        encryption_proofs::single_property_verifier,
        wellformedness_proof::{WellformednessProverAwaitingChallenge, WellformednessVerifier},
        CommitmentWitness,
    },
    errors::{ErrorKind, Fallible},
    mercat::{
        Account, AssetMemo, AssetTransactionAuditor, AssetTransactionIssuer,
        AssetTransactionMediator, AssetTransactionVerifier, AuditorPayload, EncryptedAmount,
        EncryptionKeys, EncryptionPubKey, InitializedAssetTx, JustifiedAssetTx, PubAccount,
    },
    Balance,
};

use bulletproofs::PedersenGens;
use rand_core::{CryptoRng, RngCore};
use sp_std::vec::Vec;
use zeroize::Zeroizing;

/// Helper function to verify the proofs on an asset initialization transaction.
fn asset_issuance_init_verify_proofs(
    asset_tx: &InitializedAssetTx,
    issr_pub_account: &PubAccount,
    mdtr_enc_pub_key: &EncryptionPubKey,
) -> Fallible<()> {
    let gens = PedersenGens::default();

    // Verify the proof of encrypting the same asset type as the account type.
    single_property_verifier(
        &EncryptingSameValueVerifier {
            pub_key1: issr_pub_account.memo.owner_enc_pub_key,
            pub_key2: *mdtr_enc_pub_key,
            cipher1: issr_pub_account.enc_asset_id,
            cipher2: asset_tx.enc_asset_id,
            pc_gens: &gens,
        },
        asset_tx.asset_id_equal_cipher_proof,
    )?;

    // Verify the proof of memo's wellformedness.
    single_property_verifier(
        &WellformednessVerifier {
            pub_key: issr_pub_account.memo.owner_enc_pub_key,
            cipher: asset_tx.memo.enc_issued_amount,
            pc_gens: &gens,
        },
        asset_tx.balance_wellformedness_proof,
    )?;

    Ok(())
}

fn asset_issuance_init_verify(
    asset_tx: &InitializedAssetTx,
    issr_pub_account: &PubAccount,
    mdtr_enc_pub_key: &EncryptionPubKey,
    auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
) -> Fallible<()> {
    asset_issuance_init_verify_proofs(asset_tx, issr_pub_account, mdtr_enc_pub_key)?;

    // Verify auditors payload.
    verify_auditor_payload(
        &asset_tx.auditors_payload,
        auditors_enc_pub_keys,
        issr_pub_account.memo.owner_enc_pub_key,
        asset_tx.memo.enc_issued_amount,
    )
}

fn verify_auditor_payload(
    auditors_payload: &[AuditorPayload],
    auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
    issuer_enc_pub_key: EncryptionPubKey,
    issuer_enc_amount: EncryptedAmount,
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
                                pub_key1: issuer_enc_pub_key,
                                pub_key2: *auditor_pub_key,
                                cipher1: issuer_enc_amount,
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

// -------------------------------------------------------------------------------------
// -                                    Issuer                                         -
// -------------------------------------------------------------------------------------

/// The confidential transaction issuer issues an asset for an issuer account, and
/// encrypts the metadata to the mediator's public key.
pub struct AssetIssuer {}

impl AssetTransactionIssuer for AssetIssuer {
    fn initialize_asset_transaction<T: RngCore + CryptoRng>(
        &self,
        tx_id: u32,
        issr_account: &Account,
        mdtr_pub_key: &EncryptionPubKey,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<InitializedAssetTx> {
        let gens = PedersenGens::default();

        // Encrypt the asset_id with mediator's public key.
        let mdtr_enc_asset_id = mdtr_pub_key.encrypt(&issr_account.scrt.asset_id_witness);

        // Encrypt the balance issued to mediator's public key.
        let (_, mdtr_enc_amount) = mdtr_pub_key.const_time_encrypt_value(amount.into(), rng);

        // Encrypt the balance to issuer's public key (memo).
        let (issr_amount_witness, issr_enc_amount) = issr_account
            .scrt
            .enc_keys
            .pblc
            .encrypt_value(amount.into(), rng);
        let memo = AssetMemo {
            enc_issued_amount: issr_enc_amount,
            tx_id,
        };

        // Proof of encrypting the same asset type as the account type.
        let same_asset_id_cipher_proof = single_property_prover(
            EncryptingSameValueProverAwaitingChallenge {
                pub_key1: issr_account.scrt.enc_keys.pblc,
                pub_key2: *mdtr_pub_key,
                w: Zeroizing::new(issr_account.scrt.asset_id_witness.clone()),
                pc_gens: &gens,
            },
            rng,
        )?;

        // Proof of memo's wellformedness.
        let memo_wellformedness_proof = single_property_prover(
            WellformednessProverAwaitingChallenge {
                pub_key: issr_account.scrt.enc_keys.pblc,
                w: Zeroizing::new(issr_amount_witness.clone()),
                pc_gens: &gens,
            },
            rng,
        )?;

        // Proof of memo's correctness.
        let memo_correctness_proof = single_property_prover(
            CorrectnessProverAwaitingChallenge {
                pub_key: issr_account.scrt.enc_keys.pblc,
                w: issr_amount_witness.clone(),
                pc_gens: &gens,
            },
            rng,
        )?;

        // Add the necessary payload for auditors.
        let auditors_payload = add_asset_transaction_auditor(
            auditors_enc_pub_keys,
            &issr_account.scrt.enc_keys.pblc,
            &issr_amount_witness,
            rng,
        )?;

        // Bundle the issuance data.
        Ok(InitializedAssetTx {
            account_id: issr_account.pblc.id,
            enc_asset_id: mdtr_enc_asset_id,
            enc_amount_for_mdtr: mdtr_enc_amount,
            memo,
            asset_id_equal_cipher_proof: same_asset_id_cipher_proof,
            balance_wellformedness_proof: memo_wellformedness_proof,
            balance_correctness_proof: memo_correctness_proof,
            auditors_payload,
        })
    }
}

fn add_asset_transaction_auditor<T: RngCore + CryptoRng>(
    auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
    issuer_enc_pub_key: &EncryptionPubKey,
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
                    pub_key1: *issuer_enc_pub_key,
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

// -------------------------------------------------------------------------------------
// -                                    Validator                                      -
// -------------------------------------------------------------------------------------

pub struct AssetValidator {}

/// Called by validators to verify the ZKP of the wellformedness of encrypted balance.
fn verify_initialization(
    asset_tx: &InitializedAssetTx,
    issr_pub_account: &PubAccount,
    mdtr_enc_pub_key: &EncryptionPubKey,
    auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
) -> Fallible<()> {
    Ok(asset_issuance_init_verify(
        asset_tx,
        issr_pub_account,
        mdtr_enc_pub_key,
        auditors_enc_pub_keys,
    )?)
}

impl AssetTransactionVerifier for AssetValidator {
    /// Called by validators to verify the justification and processing of the transaction.
    fn verify_asset_transaction(
        &self,
        justified_asset_tx: &JustifiedAssetTx,
        issr_account: &PubAccount,
        issr_init_balance: &EncryptedAmount,
        mdtr_enc_pub_key: &EncryptionPubKey,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
    ) -> Fallible<EncryptedAmount> {
        // Verify issuer's initialization proofs.
        let initialized_asset_tx = justified_asset_tx.init_data.clone();
        verify_initialization(
            &initialized_asset_tx,
            &issr_account,
            mdtr_enc_pub_key,
            auditors_enc_pub_keys,
        )?;

        // After successfully verifying the transaction, validator deposits the amount
        // to issuer's account (aka processing phase).
        let updated_issr_balance = crate::mercat::account::deposit(
            issr_init_balance,
            &initialized_asset_tx.memo.enc_issued_amount,
        );

        Ok(updated_issr_balance)
    }
}

// -------------------------------------------------------------------------------------
// -                                    Mediator                                       -
// -------------------------------------------------------------------------------------

pub struct AssetMediator {}

impl AssetTransactionMediator for AssetMediator {
    /// Justifies and processes a confidential asset issue transaction. This method is called
    /// by mediator. Corresponds to `JustifyAssetTx` and `ProcessCTx` of MERCAT paper.
    /// If the transaction is justified, it will be processed immediately.
    fn justify_asset_transaction(
        &self,
        initialized_asset_tx: InitializedAssetTx,
        issr_pub_account: &PubAccount,
        mdtr_enc_keys: &EncryptionKeys,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
    ) -> Fallible<JustifiedAssetTx> {
        let gens = PedersenGens::default();

        // Mediator revalidates all proofs.
        asset_issuance_init_verify(
            &initialized_asset_tx,
            issr_pub_account,
            &mdtr_enc_keys.pblc,
            auditors_enc_pub_keys,
        )?;

        // Mediator decrypts the encrypted amount and uses it to verify the correctness proof.
        let amount = mdtr_enc_keys
            .scrt
            .const_time_decrypt(&initialized_asset_tx.enc_amount_for_mdtr)?;

        single_property_verifier(
            &CorrectnessVerifier {
                value: amount.into(),
                pub_key: issr_pub_account.memo.owner_enc_pub_key,
                cipher: initialized_asset_tx.memo.enc_issued_amount,
                pc_gens: &gens,
            },
            initialized_asset_tx.balance_correctness_proof,
        )?;

        Ok(JustifiedAssetTx {
            init_data: initialized_asset_tx,
        })
    }
}

// ------------------------------------------------------------------------------------------------
// -                                          Auditor                                           -
// ------------------------------------------------------------------------------------------------

/// Asset transaction auditor.
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct AssetAuditor {}

impl AssetTransactionAuditor for AssetAuditor {
    /// Verify the initialized, and justified transactions.
    /// Audit the sender's encrypted amount.
    fn audit_asset_transaction(
        &self,
        justified_asset_tx: &JustifiedAssetTx,
        issuer_account: &PubAccount,
        mdtr_enc_pub_key: &EncryptionPubKey,
        auditor_enc_key: &(u32, EncryptionKeys),
    ) -> Fallible<()> {
        let gens = PedersenGens::default();

        // Verify issuer's initialization proofs.
        let initialized_asset_tx = justified_asset_tx.init_data.clone();
        asset_issuance_init_verify_proofs(&initialized_asset_tx, issuer_account, mdtr_enc_pub_key)?;

        // If all checks pass, decrypt the encrypted amount and verify issuer's correctness proof.
        let _: Fallible<()> = initialized_asset_tx
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
                            pub_key: issuer_account.memo.owner_enc_pub_key,
                            cipher: initialized_asset_tx.memo.enc_issued_amount,
                            pc_gens: &gens,
                        },
                        initialized_asset_tx.balance_correctness_proof,
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
        asset_proofs::{CommitmentWitness, ElgamalSecretKey},
        errors::ErrorKind,
        mercat::{
            account::{convert_asset_ids, AccountCreator},
            AccountCreatorInitializer, AccountMemo, EncryptionKeys, SecAccount,
        },
        AssetId,
    };
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use wasm_bindgen_test::*;

    #[test]
    #[wasm_bindgen_test]
    fn asset_issuance_and_validation() {
        // ----------------------- Setup
        let mut rng = StdRng::from_seed([10u8; 32]);
        let issued_amount: Balance = 20u32;

        // Generate keys for the issuer.
        let issuer_elg_secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let issuer_enc_key = EncryptionKeys {
            pblc: issuer_elg_secret_key.get_public_key(),
            scrt: issuer_elg_secret_key,
        };
        let asset_id = AssetId::from(1);

        let issuer_secret_account = SecAccount {
            enc_keys: issuer_enc_key.clone(),
            asset_id_witness: CommitmentWitness::from((asset_id.into(), &mut rng)),
        };

        let account_id = 1234u32;
        let valid_asset_ids: Vec<AssetId> =
            vec![1, 2, 3].iter().map(|id| AssetId::from(*id)).collect();
        let valid_asset_ids = convert_asset_ids(valid_asset_ids);

        let account_creator = AccountCreator {};
        let tx_id = 0;
        let issuer_account_tx = account_creator
            .create(
                tx_id,
                &issuer_secret_account,
                &valid_asset_ids,
                account_id,
                &mut rng,
            )
            .unwrap();
        let issuer_public_account = issuer_account_tx.pub_account;
        let issuer_init_balance = issuer_account_tx.initial_balance;
        let issuer_account = Account {
            pblc: issuer_public_account.clone(),
            scrt: issuer_secret_account,
        };

        // Generate keys for the mediator.
        let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let mediator_enc_key = EncryptionKeys {
            pblc: mediator_elg_secret_key.get_public_key(),
            scrt: mediator_elg_secret_key,
        };

        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        // ----------------------- Initialization
        let tx_id = tx_id + 1;
        let issuer = AssetIssuer {};
        let asset_tx = issuer
            .initialize_asset_transaction(
                tx_id,
                &issuer_account,
                &mediator_enc_key.pblc,
                &[],
                issued_amount,
                &mut rng,
            )
            .unwrap();

        // ----------------------- Justification
        let mediator = AssetMediator {};
        let justified_tx = mediator
            .justify_asset_transaction(asset_tx, &issuer_public_account, &mediator_enc_key, &[])
            .unwrap();

        // Positive test.
        let validator = AssetValidator {};
        let updated_issuer_balance = validator
            .verify_asset_transaction(
                &justified_tx,
                &issuer_public_account,
                &issuer_init_balance,
                &mediator_enc_key.pblc,
                &[],
            )
            .unwrap();

        // ----------------------- Processing
        // Check that the issued amount is added to the account balance.
        assert!(issuer_enc_key
            .scrt
            .verify(&updated_issuer_balance, &issued_amount.into())
            .is_ok());
    }

    fn asset_issuance_auditing_helper(
        issuer_auditor_list: &[(u32, EncryptionPubKey)],
        mediator_auditor_list: &[(u32, EncryptionPubKey)],
        mediator_check_fails: bool,
        validator_auditor_list: &[(u32, EncryptionPubKey)],
        validator_check_fails: bool,
        auditors_list: &[(u32, EncryptionKeys)],
    ) {
        // ----------------------- Setup
        let mut rng = StdRng::from_seed([10u8; 32]);
        let issued_amount: Balance = 20u32;

        // Generate keys for the issuer.
        let issuer_elg_secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let issuer_enc_key = EncryptionKeys {
            pblc: issuer_elg_secret_key.get_public_key(),
            scrt: issuer_elg_secret_key,
        };
        let asset_id = AssetId::from(1);

        let issuer_secret_account = SecAccount {
            enc_keys: issuer_enc_key.clone(),
            asset_id_witness: CommitmentWitness::from((asset_id.into(), &mut rng)),
        };

        let pub_account_enc_asset_id = issuer_enc_key
            .pblc
            .encrypt(&issuer_secret_account.asset_id_witness);

        // Note that we use default proof values since we don't reverify these proofs during asset issuance.
        let issuer_public_account = PubAccount {
            id: 1,
            enc_asset_id: pub_account_enc_asset_id,
            memo: AccountMemo {
                owner_enc_pub_key: issuer_enc_key.pblc,
            },
        };
        // Set the initial encrypted balance to 0.
        let issuer_init_balance = EncryptedAmount::default();
        let issuer_account = Account {
            pblc: issuer_public_account.clone(),
            scrt: issuer_secret_account,
        };

        // Generate keys for the mediator.
        let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let mediator_enc_key = EncryptionKeys {
            pblc: mediator_elg_secret_key.get_public_key(),
            scrt: mediator_elg_secret_key,
        };

        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        // ----------------------- Initialization
        let issuer = AssetIssuer {};
        let asset_tx = issuer
            .initialize_asset_transaction(
                1234u32,
                &issuer_account,
                &mediator_enc_key.pblc,
                issuer_auditor_list,
                issued_amount,
                &mut rng,
            )
            .unwrap();

        // ----------------------- Justification
        let mediator = AssetMediator {};
        let result = mediator.justify_asset_transaction(
            asset_tx,
            &issuer_public_account,
            &mediator_enc_key,
            mediator_auditor_list,
        );
        if mediator_check_fails {
            assert_err!(result, ErrorKind::AuditorPayloadError);
            return;
        }

        let justified_tx = result.unwrap();

        let validator = AssetValidator {};
        let result = validator.verify_asset_transaction(
            &justified_tx,
            &issuer_public_account,
            &issuer_init_balance,
            &mediator_enc_key.pblc,
            validator_auditor_list,
        );
        if validator_check_fails {
            assert_err!(result, ErrorKind::AuditorPayloadError);
            return;
        }

        let updated_issuer_balance = result.unwrap();
        // ----------------------- Processing
        // Check that the issued amount is added to the account balance.
        assert!(issuer_enc_key
            .scrt
            .verify(&updated_issuer_balance, &issued_amount.into())
            .is_ok());

        // ----------------------- Auditing
        let _ = auditors_list.iter().map(|auditor| {
            let transaction_auditor = AssetAuditor {};
            assert!(transaction_auditor
                .audit_asset_transaction(
                    &justified_tx,
                    &issuer_public_account,
                    &mediator_enc_key.pblc,
                    auditor,
                )
                .is_ok());
        });
    }

    fn gen_enc_key_pair(seed: u8) -> EncryptionKeys {
        let mut rng = StdRng::from_seed([seed; 32]);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        EncryptionKeys {
            pblc: elg_pub,
            scrt: elg_secret,
        }
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_asset_transaction_auditor() {
        // Make imaginary auditors.
        let auditors_num = 5u32;
        let auditors_secret_vec: Vec<(u32, EncryptionKeys)> = (0..auditors_num)
            .map(|index| {
                let auditor_keys = gen_enc_key_pair(index as u8);
                (index, auditor_keys)
            })
            .collect();
        let auditors_secret_account_list = auditors_secret_vec.as_slice();

        let auditors_vec: Vec<(u32, EncryptionPubKey)> = auditors_secret_vec
            .iter()
            .map(|a| (a.0, a.1.pblc))
            .collect();

        let auditors_list = auditors_vec.as_slice();

        // Positive tests.

        // Include `auditors_num` auditors.
        asset_issuance_auditing_helper(
            auditors_list,
            auditors_list,
            false,
            auditors_list,
            false,
            auditors_secret_account_list,
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
        let mediator_auditor_list = mediator_auditor_list.as_slice();

        let validator_auditor_list = vec![
            auditors_vec[4],
            auditors_vec[3],
            auditors_vec[2],
            auditors_vec[1],
            auditors_vec[0],
        ];
        let validator_auditor_list = validator_auditor_list.as_slice();

        asset_issuance_auditing_helper(
            auditors_list,
            mediator_auditor_list,
            false,
            validator_auditor_list,
            false,
            auditors_secret_account_list,
        );

        // Asset doesn't have any auditors.
        asset_issuance_auditing_helper(&[], &[], false, &[], false, &[]);

        // Negative tests.

        // Sender misses an auditor. Mediator catches it.
        let four_auditor_list = vec![
            auditors_vec[1],
            auditors_vec[0],
            auditors_vec[3],
            auditors_vec[2],
        ];
        let four_auditor_list = four_auditor_list.as_slice();

        asset_issuance_auditing_helper(
            &four_auditor_list,
            mediator_auditor_list,
            true,
            validator_auditor_list,
            true,
            auditors_secret_account_list,
        );

        // Sender and mediator miss an auditor, but validator catches them.
        asset_issuance_auditing_helper(
            &four_auditor_list,
            &four_auditor_list,
            false,
            validator_auditor_list,
            true,
            auditors_secret_account_list,
        );

        // Sender doesn't include any auditors. Mediator catches it.
        asset_issuance_auditing_helper(
            &[],
            mediator_auditor_list,
            true,
            validator_auditor_list,
            true,
            auditors_secret_account_list,
        );

        // Sender and mediator don't believe in auditors but validator does.
        asset_issuance_auditing_helper(
            &[],
            &[],
            false,
            validator_auditor_list,
            true,
            auditors_secret_account_list,
        );
    }
}
