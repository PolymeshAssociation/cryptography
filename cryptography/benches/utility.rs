use cryptography::{
    asset_proofs::{CommitmentWitness, ElgamalSecretKey},
    mercat::{
        account::{deposit, AccountCreator},
        Account, AccountCreatorInitializer, EncryptedAmount, EncryptionKeys, EncryptionPubKey,
        MediatorAccount, PubAccount, PubAccountTx, SecAccount,
    },
    AssetId,
};
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};

pub fn issue_assets<R: RngCore + CryptoRng>(
    rng: &mut R,
    pub_account: &PubAccount,
    init_balance: &EncryptedAmount,
    amount: u32,
) -> EncryptedAmount {
    let (_, encrypted_amount) = pub_account
        .owner_enc_pub_key
        .encrypt_value(amount.into(), rng);
    deposit(init_balance, &encrypted_amount)
}

#[allow(dead_code)]
pub fn generate_mediator_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (EncryptionPubKey, MediatorAccount) {
    let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(rng));
    let mediator_enc_key = EncryptionKeys {
        public: mediator_elg_secret_key.get_public_key(),
        secret: mediator_elg_secret_key,
    };

    (
        mediator_enc_key.public,
        MediatorAccount {
            encryption_key: mediator_enc_key,
        },
    )
}

#[allow(dead_code)]
pub fn create_account_with_amount<R: RngCore + CryptoRng>(
    rng: &mut R,
    asset_id: &AssetId,
    valid_asset_ids: &Vec<Scalar>,
    initial_amount: u32,
) -> (Account, EncryptedAmount) {
    let secret_account = gen_keys(rng, asset_id);

    let account_creator = AccountCreator;
    let pub_account_tx = account_creator
        .create(&secret_account, valid_asset_ids, rng)
        .unwrap();
    let account = Account {
        secret: secret_account,
        public: pub_account_tx.pub_account,
    };
    let initial_balance = if initial_amount > 0 {
        issue_assets(
            rng,
            &account.public,
            &pub_account_tx.initial_balance,
            initial_amount,
        )
    } else {
        pub_account_tx.initial_balance
    };

    (account, initial_balance)
}

#[allow(dead_code)]
pub fn create_account<R: RngCore + CryptoRng>(
    rng: &mut R,
    asset_id: &AssetId,
    valid_asset_ids: &Vec<Scalar>,
) -> PubAccountTx {
    let secret_account = gen_keys(rng, asset_id);

    let account_creator = AccountCreator;
    account_creator
        .create(&secret_account, valid_asset_ids, rng)
        .unwrap()
}

pub fn gen_keys<R: RngCore + CryptoRng>(rng: &mut R, asset_id: &AssetId) -> SecAccount {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
        public: elg_pub,
        secret: elg_secret,
    };

    let asset_id_witness = CommitmentWitness::new(asset_id.clone().into(), Scalar::random(rng));

    SecAccount {
        enc_keys,
        asset_id_witness,
    }
}
