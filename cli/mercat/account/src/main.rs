mod input;

use cryptography::{
    asset_proofs::{CommitmentWitness, ElgamalSecretKey},
    mercat::{account::create_account, EncryptionKeys, SecAccount},
    AssetId,
};
use curve25519_dalek::scalar::Scalar;
use env_logger;
use input::{parse_input, CLI};
use log::info;
use mercat_common::{
    errors::Error, get_asset_ids, init_print_logger, remove_file, save_to_file, OFF_CHAIN_DIR,
    ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE, SECRET_ACCOUNT_FILE,
};
use metrics::timing;
use rand::{rngs::StdRng, SeedableRng};
use rand::{CryptoRng, RngCore};
use schnorrkel::{ExpansionMode, MiniSecretKey};
use std::convert::TryFrom;
use std::{convert::TryInto, path::PathBuf, time::Instant};

fn main() {
    info!("Starting the program.");
    env_logger::init();
    init_print_logger();

    let parse_arg_timer = Instant::now();
    let args = parse_input().unwrap();
    timing!("account.argument_parse", parse_arg_timer, Instant::now());

    match args {
        CLI::Create(cfg) => process_create_account(cfg).unwrap(),
        CLI::Destroy { user, db_dir } => process_destroy_account(user, db_dir).unwrap(),
    };
}

fn process_create_account(cfg: input::AccountGenInfo) -> Result<(), Error> {
    // Setup the rng
    let seed = cfg.seed.ok_or(Error::EmptySeed)?;
    let seed: &[u8] = &base64::decode(seed).map_err(|e| Error::SeedDecodeError { error: e })?;
    let seed = seed
        .try_into()
        .map_err(|_| Error::SeedLengthError { length: seed.len() })?;
    let mut rng = StdRng::from_seed(seed);

    // Generate the account
    let db_dir = cfg.db_dir.ok_or(Error::EmptyDatabaseDir)?;
    let secret_account = generate_secret_account(&mut rng, cfg.ticker_id)?;
    let valid_asset_ids = get_asset_ids(db_dir.clone())?;

    let create_account_timer = Instant::now();
    let account = create_account(secret_account, &valid_asset_ids, cfg.account_id, &mut rng)
        .map_err(|error| Error::LibraryError { error })?;
    timing!("account.call_library", create_account_timer, Instant::now());

    let save_to_file_timer = Instant::now();
    // Save the secret and public account
    save_to_file(
        db_dir.clone(),
        OFF_CHAIN_DIR,
        &cfg.user,
        SECRET_ACCOUNT_FILE,
        &account.scrt,
    )?;

    save_to_file(
        db_dir,
        ON_CHAIN_DIR,
        &cfg.user,
        PUBLIC_ACCOUNT_FILE,
        &account.scrt,
    )?;

    timing!("account.save_output", save_to_file_timer, Instant::now());

    Ok(())
}

fn process_destroy_account(user: String, db_dir: Option<PathBuf>) -> Result<(), Error> {
    let account_removal_timer = Instant::now();
    let db_dir = db_dir.ok_or(Error::EmptyDatabaseDir)?;

    remove_file(db_dir.clone(), OFF_CHAIN_DIR, &user, SECRET_ACCOUNT_FILE)?;
    remove_file(db_dir, ON_CHAIN_DIR, &user, PUBLIC_ACCOUNT_FILE)?;

    timing!(
        "account.remove_account",
        account_removal_timer,
        Instant::now()
    );
    Ok(())
}

fn generate_secret_account<R: RngCore + CryptoRng>(
    rng: &mut R,
    ticker_id: String,
) -> Result<SecAccount, Error> {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
        pblc: elg_pub.into(),
        scrt: elg_secret.into(),
    };

    let asset_id = AssetId::try_from(ticker_id).map_err(|error| Error::LibraryError { error })?;
    let asset_id_witness = CommitmentWitness::new(asset_id.clone().into(), Scalar::random(rng));

    let sign_keys = MiniSecretKey::generate_with(rng).expand_to_keypair(ExpansionMode::Ed25519);

    Ok(SecAccount {
        enc_keys,
        sign_keys,
        asset_id,
        asset_id_witness,
    })
}
