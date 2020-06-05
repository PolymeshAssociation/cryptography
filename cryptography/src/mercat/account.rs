use crate::{
    asset_proofs::{
        correctness_proof::{CorrectnessProverAwaitingChallenge, CorrectnessVerifier},
        encryption_proofs::single_property_prover,
        encryption_proofs::single_property_verifier,
        membership_proof::{MembershipProofVerifier, MembershipProverAwaitingChallenge},
        one_out_of_many_proof::OooNProofGenerators,
        wellformedness_proof::{WellformednessProverAwaitingChallenge, WellformednessVerifier},
        CommitmentWitness,
    },
    errors::{ErrorKind, Fallible},
    mercat::{
        Account, AccountCreaterVerifier, AccountMemo, CorrectnessProof, EncryptedAmount,
        MembershipProof, PubAccount, PubAccountContent, SecAccount, WellformednessProof, BASE,
        EXPONENT,
    },
    AssetId, Balance,
};
use bulletproofs::PedersenGens;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::StdRng;
use sp_application_crypto::sr25519;
use sp_core::crypto::Pair;
use zeroize::Zeroizing;

// ------------------------------------------------------------------------------------------------
// -                                        Any User                                              -
// ------------------------------------------------------------------------------------------------

pub fn create_account(
    scrt: SecAccount,
    valid_asset_ids: Vec<AssetId>,
    account_id: u32,
    rng: &mut StdRng,
) -> Fallible<Account> {
    let balance_blinding = Scalar::random(rng);
    let gens = &PedersenGens::default();

    // Encrypt asset id and prove that the encrypted asset is wellformed
    let enc_asset_id = scrt.enc_keys.pblc.key.encrypt(&scrt.asset_id_witness);

    let asset_wellformedness_proof = WellformednessProof::from(single_property_prover(
        WellformednessProverAwaitingChallenge {
            pub_key: scrt.enc_keys.pblc.key,
            w: Zeroizing::new(scrt.asset_id_witness.clone()),
            pc_gens: &gens,
        },
        rng,
    )?);

    // Encrypt the balance and prove that the encrypted balance is correct
    let balance: Balance = 0;
    let balance_witness = CommitmentWitness::new(balance.into(), balance_blinding);
    let enc_balance = EncryptedAmount::from(scrt.enc_keys.pblc.key.encrypt(&balance_witness));

    let initial_balance_correctness_proof = CorrectnessProof::from(single_property_prover(
        CorrectnessProverAwaitingChallenge {
            pub_key: scrt.enc_keys.pblc.key,
            w: balance_witness,
            pc_gens: &gens,
        },
        rng,
    )?);

    // Prove that the asset id is among the list of publicly known asset ids
    let membership_blinding = Scalar::random(rng);
    let generators = &OooNProofGenerators::new(EXPONENT, BASE);
    let asset_id = Scalar::from(scrt.asset_id.clone());
    let secret_element_com = generators.com_gens.commit(asset_id, membership_blinding);
    let elements_set: Vec<Scalar> = valid_asset_ids
        .iter()
        .map(|m| Scalar::from(m.clone()))
        .collect();
    let (init, response) = single_property_prover(
        MembershipProverAwaitingChallenge::new(
            asset_id,
            membership_blinding,
            generators,
            elements_set.as_slice(),
            BASE,
            EXPONENT,
        )?,
        rng,
    )?;

    let asset_membership_proof = MembershipProof {
        init,
        response,
        commitment: secret_element_com,
    };

    // Gather content and sign it
    let content = PubAccountContent {
        id: account_id,
        enc_asset_id: enc_asset_id.into(),
        enc_balance,
        asset_wellformedness_proof,
        asset_membership_proof,
        initial_balance_correctness_proof,
        memo: AccountMemo::from((scrt.enc_keys.pblc, scrt.sign_keys.pblc())),
    };

    let initial_sig = scrt.sign_keys.pair.sign(&content.to_bytes()?);

    Ok(Account {
        pblc: PubAccount {
            content,
            initial_sig,
        },
        scrt,
    })
}

#[inline(always)]
fn set_enc_balance(account: PubAccount, enc_balance: EncryptedAmount) -> PubAccount {
    PubAccount {
        content: PubAccountContent {
            id: account.content.id,
            enc_asset_id: account.content.enc_asset_id,
            enc_balance, // the new balance
            asset_wellformedness_proof: account.content.asset_wellformedness_proof,
            asset_membership_proof: account.content.asset_membership_proof,
            initial_balance_correctness_proof: account.content.initial_balance_correctness_proof,
            memo: account.content.memo,
        },
        initial_sig: account.initial_sig,
    }
}

pub fn deposit(account: PubAccount, enc_amount: EncryptedAmount) -> PubAccount {
    let enc_balance = EncryptedAmount::from(account.content.enc_balance.cipher + enc_amount.cipher);
    set_enc_balance(account, enc_balance)
}

pub fn withdraw(account: PubAccount, enc_amount: EncryptedAmount) -> PubAccount {
    let enc_balance = EncryptedAmount::from(account.content.enc_balance.cipher - enc_amount.cipher);
    set_enc_balance(account, enc_balance)
}

// ------------------------------------------------------------------------------------------------
// -                                          Validator                                           -
// ------------------------------------------------------------------------------------------------

pub struct AccountValidator {}

impl AccountCreaterVerifier for AccountValidator {
    fn verify(&self, account: &PubAccount, valid_asset_ids: Vec<AssetId>) -> Fallible<()> {
        let gens = &PedersenGens::default();
        ensure!(
            sr25519::Pair::verify(
                &account.initial_sig,
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
        let balance: Balance = 0;
        single_property_verifier(
            &CorrectnessVerifier {
                value: balance.into(),
                pub_key: account.content.memo.owner_enc_pub_key.key,
                cipher: account.content.enc_balance.cipher,
                pc_gens: &gens,
            },
            account.content.initial_balance_correctness_proof.init,
            account.content.initial_balance_correctness_proof.response,
        )?;

        // Verify that the asset is from the proper asset list
        let membership_proof = account.content.asset_membership_proof.clone();
        let generators = &OooNProofGenerators::new(EXPONENT, BASE);
        let elements_set = valid_asset_ids
            .into_iter()
            .map(|m| Scalar::from(m))
            .collect::<Vec<_>>();
        single_property_verifier(
            &MembershipProofVerifier {
                secret_element_com: membership_proof.commitment,
                generators,
                elements_set: elements_set.as_slice(),
            },
            membership_proof.init,
            membership_proof.response,
        )?;

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
        asset_proofs::ElgamalSecretKey,
        mercat::{EncryptionKeys, SigningKeys},
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
        let asset_id = AssetId::from(1);
        let valid_asset_ids: Vec<AssetId> = vec![1, 2, 3]
            .iter()
            .map(|id| AssetId::from(id.clone()))
            .collect();
        let account_id = 2;
        let asset_id_witness = CommitmentWitness::from((asset_id.clone().into(), &mut rng));
        let scrt_account = SecAccount {
            enc_keys,
            sign_keys,
            asset_id,
            asset_id_witness,
        };

        // ----------------------- test

        let sndr_account = create_account(
            scrt_account.clone(),
            valid_asset_ids.clone(),
            account_id,
            &mut rng,
        )
        .unwrap();
        let decrypted_balance = sndr_account.decrypt_balance().unwrap();
        assert_eq!(decrypted_balance, 0);

        let account_vldtr = AccountValidator {};
        let result = account_vldtr.verify(&sndr_account.pblc, valid_asset_ids);
        result.unwrap();
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_account_updates() {
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
        let asset_id = AssetId::from(1);
        let valid_asset_ids: Vec<AssetId> = vec![1, 2, 3]
            .iter()
            .map(|id| AssetId::from(id.clone()))
            .collect();
        let account_id = 2;
        let asset_id_witness = CommitmentWitness::from((asset_id.clone().into(), &mut rng));
        let scrt_account = SecAccount {
            enc_keys,
            sign_keys,
            asset_id,
            asset_id_witness,
        };

        // ----------------------- test

        let account =
            create_account(scrt_account, valid_asset_ids.clone(), account_id, &mut rng).unwrap();
        let balance = account.decrypt_balance().unwrap();
        assert_eq!(balance, 0);

        let ten: Balance = 10;
        let ten = EncryptedAmount::from(account.scrt.enc_keys.pblc.key.encrypt(
            &CommitmentWitness::new(ten.into(), Scalar::random(&mut rng)),
        ));
        let five: Balance = 5;
        let five = EncryptedAmount::from(account.scrt.enc_keys.pblc.key.encrypt(
            &CommitmentWitness::new(five.into(), Scalar::random(&mut rng)),
        ));
        let account = Account {
            pblc: deposit(account.pblc, ten),
            scrt: account.scrt,
        };

        let balance = account.decrypt_balance().unwrap();
        assert_eq!(balance, 10);

        let account = Account {
            pblc: withdraw(account.pblc, five),
            scrt: account.scrt,
        };

        let balance = account.decrypt_balance().unwrap();
        assert_eq!(balance, 5);
    }
}
