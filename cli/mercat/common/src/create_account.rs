use crate::{
    create_rng_from_seed, errors::Error, get_asset_ids, save_object, OFF_CHAIN_DIR, ON_CHAIN_DIR,
    PUBLIC_ACCOUNT_FILE, SECRET_ACCOUNT_FILE,
};
use cryptography::{
    asset_id_from_ticker,
    asset_proofs::{CommitmentWitness, ElgamalSecretKey},
    mercat::{account::create_account, EncryptionKeys, SecAccount},
};
use metrics::timing;
use rand::{CryptoRng, RngCore};
use schnorrkel::{ExpansionMode, MiniSecretKey};

use curve25519_dalek::scalar::Scalar;
use std::{path::PathBuf, time::Instant};

pub fn process_create_account(
    seed: Option<String>,
    db_dir: PathBuf,
    ticker: String,
    account_id: u32,
    user: String,
) -> Result<(), Error> {
    // Setup the rng
    let mut rng = create_rng_from_seed(seed)?;

    // Create the account
    let secret_account = create_secret_account(&mut rng, ticker.clone())?;
    let valid_asset_ids = get_asset_ids(db_dir.clone())?;

    let create_account_timer = Instant::now();
    let account = create_account(secret_account, &valid_asset_ids, account_id, &mut rng)
        .map_err(|error| Error::LibraryError { error })?;
    timing!("account.call_library", create_account_timer, Instant::now());

    // Save the artifacts to file.
    let save_to_file_timer = Instant::now();
    save_object(
        db_dir.clone(),
        OFF_CHAIN_DIR,
        &user,
        SECRET_ACCOUNT_FILE,
        &account.scrt,
    )?;

    save_object(
        db_dir,
        ON_CHAIN_DIR,
        &user,
        PUBLIC_ACCOUNT_FILE,
        &account.pblc,
    )?;

    timing!("account.save_output", save_to_file_timer, Instant::now());

    Ok(())
}

fn create_secret_account<R: RngCore + CryptoRng>(
    rng: &mut R,
    ticker_id: String,
) -> Result<SecAccount, Error> {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
        pblc: elg_pub.into(),
        scrt: elg_secret.into(),
    };

    let asset_id =
        asset_id_from_ticker(&ticker_id).map_err(|error| Error::LibraryError { error })?;
    let asset_id_witness = CommitmentWitness::new(asset_id.clone().into(), Scalar::random(rng));

    let sign_keys = MiniSecretKey::generate_with(rng).expand_to_keypair(ExpansionMode::Ed25519);

    Ok(SecAccount {
        enc_keys,
        sign_keys,
        asset_id,
        asset_id_witness,
    })
}
