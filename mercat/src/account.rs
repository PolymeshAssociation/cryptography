use crate::{
    AccountCreatorInitializer, AccountCreatorVerifier, EncryptedAmount, PubAccount, PubAccountTx,
    SecAccount, BASE, EXPONENT,
};
use cryptography_core::{
    asset_proofs::{
        bulletproofs::PedersenGens,
        correctness_proof::{CorrectnessProverAwaitingChallenge, CorrectnessVerifier},
        encryption_proofs::single_property_prover,
        encryption_proofs::single_property_verifier,
        errors::Fallible,
        membership_proof::{MembershipProofVerifier, MembershipProverAwaitingChallenge},
        one_out_of_many_proof::OooNProofGenerators,
        wellformedness_proof::{WellformednessProverAwaitingChallenge, WellformednessVerifier},
        AssetId, Balance, CommitmentWitness,
    },
    curve25519_dalek::scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};

use sp_std::vec::Vec;
use zeroize::Zeroizing;

// ------------------------------------------------------------------------------------------------
// -                                        Any User                                              -
// ------------------------------------------------------------------------------------------------

pub fn convert_asset_ids(valid_asset_ids: Vec<AssetId>) -> Vec<Scalar> {
    valid_asset_ids
        .into_iter()
        .map(Scalar::from)
        .collect::<Vec<_>>()
}

pub struct AccountCreator;

impl AccountCreatorInitializer for AccountCreator {
    fn create<T: RngCore + CryptoRng>(
        &self,
        secret: &SecAccount,
        valid_asset_ids: &[Scalar],
        rng: &mut T,
    ) -> Fallible<PubAccountTx> {
        let balance_blinding = Scalar::random(rng);
        let gens = &PedersenGens::default();

        // Encrypt asset id and prove that the encrypted asset is wellformed
        let enc_asset_id = secret.enc_keys.public.encrypt(&secret.asset_id_witness);

        let asset_wellformedness_proof = single_property_prover(
            WellformednessProverAwaitingChallenge {
                pub_key: secret.enc_keys.public,
                w: Zeroizing::new(secret.asset_id_witness.clone()),
                pc_gens: &gens,
            },
            rng,
        )?;

        // Encrypt the balance and prove that the encrypted balance is correct
        let balance: Balance = 0;
        let balance_witness = CommitmentWitness::new(balance.into(), balance_blinding);
        let initial_balance = secret.enc_keys.public.encrypt(&balance_witness);

        let initial_balance_correctness_proof = single_property_prover(
            CorrectnessProverAwaitingChallenge {
                pub_key: secret.enc_keys.public,
                w: balance_witness,
                pc_gens: &gens,
            },
            rng,
        )?;

        // Prove that the encrypted asset id that is stored as `enc_asset_id.y` is among the list of publicly known asset ids.
        let generators = &OooNProofGenerators::new(BASE, EXPONENT);
        let asset_id = secret.asset_id_witness.value();
        let asset_membership_proof = single_property_prover(
            MembershipProverAwaitingChallenge::new(
                asset_id,
                secret.asset_id_witness.blinding(),
                generators,
                valid_asset_ids,
                BASE,
                EXPONENT,
            )?,
            rng,
        )?;

        Ok(PubAccountTx {
            pub_account: PubAccount {
                enc_asset_id,
                owner_enc_pub_key: secret.enc_keys.public,
            },
            initial_balance,
            asset_wellformedness_proof,
            asset_membership_proof,
            initial_balance_correctness_proof,
        })
    }
}

pub fn deposit(initial_balance: &EncryptedAmount, enc_amount: &EncryptedAmount) -> EncryptedAmount {
    initial_balance + enc_amount
}

pub fn withdraw(
    initial_balance: &EncryptedAmount,
    enc_amount: &EncryptedAmount,
) -> EncryptedAmount {
    initial_balance - enc_amount
}

// ------------------------------------------------------------------------------------------------
// -                                          Validator                                           -
// ------------------------------------------------------------------------------------------------

pub struct AccountValidator;

impl AccountCreatorVerifier for AccountValidator {
    fn verify(&self, account: &PubAccountTx, valid_asset_ids: &[Scalar]) -> Fallible<()> {
        let gens = &PedersenGens::default();

        // Verify that the encrypted asset id is wellformed
        single_property_verifier(
            &WellformednessVerifier {
                pub_key: account.pub_account.owner_enc_pub_key,
                cipher: account.pub_account.enc_asset_id,
                pc_gens: &gens,
            },
            account.asset_wellformedness_proof,
        )?;

        // Verify that the encrypted balance is correct
        let balance: Balance = 0;
        single_property_verifier(
            &CorrectnessVerifier {
                value: balance.into(),
                pub_key: account.pub_account.owner_enc_pub_key,
                cipher: account.initial_balance,
                pc_gens: &gens,
            },
            account.initial_balance_correctness_proof,
        )?;

        // Verify that the asset is from the proper asset list
        let membership_proof = account.asset_membership_proof.clone();
        let generators = &OooNProofGenerators::new(BASE, EXPONENT);
        single_property_verifier(
            &MembershipProofVerifier {
                secret_element_com: account.pub_account.enc_asset_id.y,
                generators,
                elements_set: valid_asset_ids,
            },
            membership_proof,
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
    use crate::EncryptionKeys;
    use cryptography_core::{asset_proofs::ElgamalSecretKey, curve25519_dalek::scalar::Scalar};
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    #[test]
    #[wasm_bindgen_test]
    fn test_account_creation_and_validation() {
        // ----------------------- setup
        let mut rng = StdRng::from_seed([10u8; 32]);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let enc_keys = EncryptionKeys {
            public: elg_pub,
            secret: elg_secret,
        };
        let asset_id = AssetId::from(1);
        let valid_asset_ids: Vec<AssetId> =
            vec![1, 2, 3].iter().map(|id| AssetId::from(*id)).collect();
        let valid_asset_ids = convert_asset_ids(valid_asset_ids);
        let asset_id_witness = CommitmentWitness::from((asset_id.into(), &mut rng));
        let secret_account = SecAccount {
            enc_keys,
            asset_id_witness,
        };

        // ----------------------- test
        let account_creator = AccountCreator;
        let sender_account_tx = account_creator
            .create(&secret_account, &valid_asset_ids, &mut rng)
            .unwrap();

        let decrypted_balance = secret_account
            .enc_keys
            .secret
            .decrypt(&sender_account_tx.initial_balance)
            .unwrap();
        assert_eq!(decrypted_balance, 0);

        let account_vldtr = AccountValidator;
        let result = account_vldtr.verify(&sender_account_tx, &valid_asset_ids);
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
            public: elg_pub,
            secret: elg_secret,
        };
        let asset_id = AssetId::from(1);
        let valid_asset_ids: Vec<AssetId> =
            vec![1, 2, 3].iter().map(|id| AssetId::from(*id)).collect();
        let valid_asset_ids = convert_asset_ids(valid_asset_ids);
        let asset_id_witness = CommitmentWitness::from((asset_id.into(), &mut rng));
        let secret_account = SecAccount {
            enc_keys,
            asset_id_witness,
        };

        // ----------------------- test
        let account_creator = AccountCreator;
        let pub_account_tx = account_creator
            .create(&secret_account, &valid_asset_ids, &mut rng)
            .unwrap();

        let balance = secret_account
            .enc_keys
            .secret
            .decrypt(&pub_account_tx.initial_balance)
            .unwrap();
        assert_eq!(balance, 0);

        let ten: Balance = 10;
        let ten = secret_account
            .enc_keys
            .public
            .encrypt_value(ten.into(), &mut rng)
            .1;
        let five: Balance = 5;
        let five = secret_account
            .enc_keys
            .public
            .encrypt_value(five.into(), &mut rng)
            .1;

        let new_enc_balance = deposit(&pub_account_tx.initial_balance, &ten);
        let balance = secret_account
            .enc_keys
            .secret
            .decrypt(&new_enc_balance)
            .unwrap();
        assert_eq!(balance, 10);

        let new_enc_balance = withdraw(&new_enc_balance, &five);
        let balance = secret_account
            .enc_keys
            .secret
            .decrypt(&new_enc_balance)
            .unwrap();
        assert_eq!(balance, 5);
    }
}
