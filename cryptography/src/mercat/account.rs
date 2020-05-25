use crate::mercat::conf_tx::{CtxReceiver, CtxSender};
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
        range_proof::{prove_within_range, verify_within_range, RangeProofInitialMessage},
        wellformedness_proof::{WellformednessProverAwaitingChallenge, WellformednessVerifier},
        CommitmentWitness,
    },
    errors::{ErrorKind, Fallible},
    mercat::{
        AccountCreater, AccountCreaterVerifier, AccountMemo, CipherEqualDifferentPubKeyProof,
        CipherEqualSamePubKeyProof, ConfidentialTransactionInitVerifier,
        ConfidentialTransactionReceiver, ConfidentialTransactionSender, ConfidentialTxMemo,
        ConfidentialTxState, CorrectnessProof, EncryptedAmount, EncryptedAssetId, EncryptionKeys,
        EncryptionPubKey, EncryptionSecKey, InRangeProof, MembershipProof, PubAccount,
        PubAccountContent, PubFinalConfidentialTxData, PubFinalConfidentialTxDataContent,
        PubInitConfidentialTxData, PubInitConfidentialTxDataContent, SecAccount, SigningKeys,
        SigningPubKey, TxSubstate, WellformednessProof,
    },
};
use bulletproofs::PedersenGens;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::StdRng;
use sp_application_crypto::sr25519;
use sp_core::crypto::Pair;
use std::convert::TryFrom;
use zeroize::Zeroizing;

// ------------------------------------------------------------------------------------------------
// -                                     Sender/Receiver                                          -
// ------------------------------------------------------------------------------------------------

// TODO create a separate struct for this

pub fn create_account(
    scrt: &SecAccount,
    valid_asset_ids: Vec<u32>,
    account_id: u32,
    rng: &mut StdRng,
) -> Fallible<PubAccount> {
    let blinding_1 = Scalar::random(rng);
    let blinding_2 = Scalar::random(rng);
    let gens = &PedersenGens::default();

    // encrypt asset id and prove that the encrypted asset is wellformed
    let asset_witness = CommitmentWitness::try_from((scrt.asset_id, blinding_1))?;
    let enc_asset_id = EncryptedAssetId::from(scrt.enc_keys.pblc.key.encrypt(&asset_witness));

    let asset_wellformedness_proof = WellformednessProof::from(single_property_prover(
        WellformednessProverAwaitingChallenge {
            pub_key: scrt.enc_keys.pblc.key,
            w: Zeroizing::new(asset_witness.clone()),
            pc_gens: &gens,
        },
        rng,
    )?);

    // encrypt the balance and prove that the encrypted balance is correct

    let balance = 0;
    let balance_witness = CommitmentWitness::try_from((balance, blinding_2))?;
    let enc_balance = EncryptedAmount::from(scrt.enc_keys.pblc.key.encrypt(&balance_witness));

    let balance_correctness_proof = CorrectnessProof::from(single_property_prover(
        CorrectnessProverAwaitingChallenge {
            pub_key: scrt.enc_keys.pblc.key,
            w: balance_witness,
            pc_gens: &gens,
        },
        rng,
    )?);

    // TODO: membership proof
    let asset_membership_proof = MembershipProof::default();

    // gather content and sign it
    let content = PubAccountContent {
        id: account_id,
        enc_asset_id,
        enc_balance,
        asset_wellformedness_proof,
        asset_membership_proof,
        balance_correctness_proof,
        memo: AccountMemo::from((scrt.enc_keys.pblc, scrt.sign_keys.pblc())),
    };

    let sig = scrt.sign_keys.pair.sign(&content.to_bytes()?);

    Ok(PubAccount { content, sig })
}

// ------------------------------------------------------------------------------------------------
// -                                          Validator                                           -
// ------------------------------------------------------------------------------------------------

pub struct AccountValidator {}

// TODO: should these have states similar to transactions?

impl AccountCreaterVerifier for AccountValidator {
    fn verify(&self, account: PubAccount) -> Fallible<()> {
        let gens = &PedersenGens::default();
        ensure!(
            sr25519::Pair::verify(
                &account.sig,
                &account.content.to_bytes()?,
                &account.content.memo.owner_sign_pub_key.key,
            ),
            ErrorKind::SignatureValidationFailure
        );

        // Verify that the encrypted asset id is wellformed
        single_property_verifier(
            &WellformednessVerifier {
                pub_key: account.content.memo.owner_enc_pub_key.key,
                cipher: account.content.enc_asset_id.cipher,
                pc_gens: &gens,
            },
            account.content.asset_wellformedness_proof.init,
            account.content.asset_wellformedness_proof.response,
        )?;

        // Verify that the encrypted balance is correct
        single_property_verifier(
            &CorrectnessVerifier {
                value: 0,
                pub_key: account.content.memo.owner_enc_pub_key.key,
                cipher: account.content.enc_balance.cipher,
                pc_gens: &gens,
            },
            account.content.balance_correctness_proof.init,
            account.content.balance_correctness_proof.response,
        )?;

        // TODO: verify that the asset is from the proper asset list

        Ok(())
    }
}

// ------------------------------------------------------------------------------------------------
// -                                            Tests                                             -
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::{
        asset_proofs::{CipherText, ElgamalSecretKey},
        mercat::{
            AccountMemo, ConfidentialTxMemo, CorrectnessProof, EncryptionKeys, EncryptionPubKey,
            MembershipProof, PubAccountContent, Signature, SigningKeys, SigningPubKey,
            WellformednessProof,
        },
    };
    use curve25519_dalek::scalar::Scalar;
    use rand::SeedableRng;
    use wasm_bindgen_test::*;

    #[test]
    #[wasm_bindgen_test]
    fn test_account_creation_and_validation() {
        // ----------------------- setup
        let mut rng = StdRng::from_seed([10u8; 32]);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let enc_keys = EncryptionKeys {
            pblc: elg_pub.into(),
            scrt: elg_secret.into(),
        };
        let pair = sr25519::Pair::from_seed(&[11u8; 32]);
        let sign_keys = SigningKeys { pair: pair.clone() };
        let asset_id = 1;
        let valid_asset_ids = vec![]; // TODO: intentionally left empty
        let account_id = 2;
        let scrt_account = SecAccount {
            enc_keys,
            sign_keys,
            asset_id,
        };

        // ----------------------- test

        let sndr_account =
            create_account(&scrt_account, valid_asset_ids, account_id, &mut rng).unwrap();

        let account_vldtr = AccountValidator {};
        let result = account_vldtr.verify(sndr_account);
        result.unwrap();
    }
}
