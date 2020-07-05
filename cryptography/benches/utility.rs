use cryptography::{
    asset_proofs::{CommitmentWitness, ElgamalSecretKey},
    mercat::{
        account::AccountCreator,
        asset::{AssetIssuer, AssetMediator, AssetValidator},
        Account, AccountCreatorInitializer, AccountMemo, AssetTransactionIssuer,
        AssetTransactionMediator, AssetTransactionVerifier, AssetTxState, EncryptionKeys,
        MediatorAccount, PubAccount, SecAccount, TxSubstate,
    },
    AssetId,
};
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use schnorrkel::{ExpansionMode, MiniSecretKey};

#[allow(dead_code)]
pub fn issue_assets<R: RngCore + CryptoRng>(
    rng: &mut R,
    account: Account,
    mediator_account: &MediatorAccount,
    mediator_pub_account: &AccountMemo,
    amount: u32,
) -> PubAccount {
    // Issuer side.
    let issuer = AssetIssuer {};
    let (asset_tx, _) = issuer
        .initialize(
            0,
            &account.scrt,
            &mediator_pub_account.owner_enc_pub_key,
            amount,
            rng,
        )
        .unwrap();

    // Mediator side.
    let mediator = AssetMediator {};
    let tx = mediator
        .justify(
            asset_tx.clone(),
            &account.pblc,
            AssetTxState::Initialization(TxSubstate::Started),
            &mediator_account.encryption_key,
            &mediator_account.signing_key,
        )
        .unwrap();

    let validator = AssetValidator {};
    let (updated_issuer_account, _) = validator
        .verify(
            &tx,
            &account.pblc,
            &mediator_pub_account.owner_enc_pub_key,
            &mediator_pub_account.owner_sign_pub_key,
        )
        .unwrap();
    updated_issuer_account
}

#[allow(dead_code)]
pub fn generate_mediator_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (AccountMemo, MediatorAccount) {
    let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(rng));
    let mediator_enc_key = EncryptionKeys {
        pblc: mediator_elg_secret_key.get_public_key().into(),
        scrt: mediator_elg_secret_key.into(),
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
    mediator_account: &MediatorAccount,
    mediator_pub_account: &AccountMemo,
    initial_amount: u32,
) -> Account {
    let secret_account = gen_keys(rng, asset_id);

    let account_creator = AccountCreator {};
    let account = account_creator
        .create(secret_account, valid_asset_ids, 0, rng)
        .unwrap();
    // If a non-zero initial amount is given issue some assets to this account.
    if initial_amount > 0 {
        Account {
            scrt: account.scrt.clone(),
            pblc: issue_assets(
                rng,
                account,
                mediator_account,
                mediator_pub_account,
                initial_amount,
            ),
        }
    } else {
        account
    }
}

#[allow(dead_code)]
pub fn create_account<R: RngCore + CryptoRng>(
    rng: &mut R,
    asset_id: &AssetId,
    valid_asset_ids: &Vec<Scalar>,
    account_id: u32,
) -> Account {
    let secret_account = gen_keys(rng, asset_id);

    let account_creator = AccountCreator {};
    account_creator
        .create(secret_account, valid_asset_ids, account_id, rng)
        .unwrap()
}

pub fn gen_keys<R: RngCore + CryptoRng>(rng: &mut R, asset_id: &AssetId) -> SecAccount {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
        pblc: elg_pub.into(),
        scrt: elg_secret.into(),
    };

    let asset_id_witness = CommitmentWitness::new(asset_id.clone().into(), Scalar::random(rng));

    let sign_keys = MiniSecretKey::generate_with(rng).expand_to_keypair(ExpansionMode::Ed25519);

    SecAccount {
        enc_keys,
        sign_keys,
        asset_id: asset_id.clone(),
        asset_id_witness,
    }
}
