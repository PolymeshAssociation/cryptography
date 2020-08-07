use cryptography::{
    asset_proofs::{CommitmentWitness, ElgamalSecretKey},
    mercat::{
        account::{deposit, AccountCreator},
        Account, AccountCreatorInitializer, AccountMemo, EncryptedAmount, EncryptionKeys,
        MediatorAccount, PubAccount, PubAccountTx, SecAccount,
    },
    AssetId,
};
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use schnorrkel::{ExpansionMode, MiniSecretKey};

pub fn issue_assets<R: RngCore + CryptoRng>(
    rng: &mut R,
    pub_account: &PubAccount,
    init_balance: &EncryptedAmount,
    amount: u32,
) -> EncryptedAmount {
    let (_, encrypted_amount) = pub_account
        .memo
        .owner_enc_pub_key
        .encrypt_value(amount.into(), rng);
    deposit(init_balance, &encrypted_amount)
}

#[allow(dead_code)]
pub fn generate_mediator_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (AccountMemo, MediatorAccount) {
    let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(rng));
    let mediator_enc_key = EncryptionKeys {
        pblc: mediator_elg_secret_key.get_public_key(),
        scrt: mediator_elg_secret_key,
    };

    let mediator_signing_pair =
        MiniSecretKey::generate_with(rng).expand_to_keypair(ExpansionMode::Ed25519);

    (
        AccountMemo::new(mediator_enc_key.pblc, mediator_signing_pair.public),
        MediatorAccount {
            encryption_key: mediator_enc_key,
            signing_key: mediator_signing_pair,
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

    let tx_id = 0;
    let account_creator = AccountCreator {};
    let pub_account_tx = account_creator
        .create(tx_id, &secret_account, valid_asset_ids, 0, rng)
        .unwrap();
    let account = Account {
        scrt: secret_account,
        pblc: pub_account_tx.content.pub_account,
    };
    let mut initial_balance = pub_account_tx.content.initial_balance;
    // If a non-zero initial amount is given issue some assets to this account.
    if initial_amount > 0 {
        initial_balance = issue_assets(
            rng,
            &account.pblc,
            &pub_account_tx.content.initial_balance,
            initial_amount,
        );
    }

    (account, initial_balance)
}

#[allow(dead_code)]
pub fn create_account<R: RngCore + CryptoRng>(
    rng: &mut R,
    asset_id: &AssetId,
    valid_asset_ids: &Vec<Scalar>,
    account_id: u32,
    tx_id: u32,
) -> PubAccountTx {
    let secret_account = gen_keys(rng, asset_id);

    let account_creator = AccountCreator {};
    account_creator
        .create(tx_id, &secret_account, valid_asset_ids, account_id, rng)
        .unwrap()
}

pub fn gen_keys<R: RngCore + CryptoRng>(rng: &mut R, asset_id: &AssetId) -> SecAccount {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
        pblc: elg_pub,
        scrt: elg_secret,
    };

    let asset_id_witness = CommitmentWitness::new(asset_id.clone().into(), Scalar::random(rng));

    let sign_keys = MiniSecretKey::generate_with(rng).expand_to_keypair(ExpansionMode::Ed25519);

    SecAccount {
        enc_keys,
        sign_keys,
        asset_id_witness,
    }
}
