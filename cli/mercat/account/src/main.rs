mod errors;
mod input;

use cryptography::{
    asset_proofs::{CommitmentWitness, ElgamalSecretKey},
    mercat::{account::create_account, EncryptionKeys, SecAccount},
    AssetId,
};
use curve25519_dalek::scalar::Scalar;
use env_logger;
use errors::Error;
use input::{parse_input, CLI};
use log::info;
use mercat_common::{get_asset_ids, init_print_logger};
use metrics::timing;
use rand::{rngs::StdRng, SeedableRng};
use schnorrkel::{ExpansionMode, MiniSecretKey};
use std::{convert::TryInto, fs::File, path::PathBuf, time::Instant};

fn main() {
    info!("Starting the program.");
    env_logger::init();
    init_print_logger();

    let start = Instant::now();
    let args = parse_input().unwrap();
    timing!("account.argument_parse", start, Instant::now());

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
    let secret_account = generate_secret_account(&mut rng);
    let valid_asset_ids = get_asset_ids();

    let start = Instant::now();
    let account = create_account(secret_account, &valid_asset_ids, cfg.account_id, &mut rng)
        .map_err(|error| Error::LibraryError { error })?;
    timing!("account.call_library", start, Instant::now());

    let start = Instant::now();
    // Save the secret account
    let db_dir = cfg.db_dir.ok_or(Error::EmptyDatabaseDir)?;
    let mut secret_file_path = db_dir.clone();
    secret_file_path.push(format!("off-chain/{}_secret_account.json", cfg.user));
    let file =
        File::create(secret_file_path.clone()).map_err(|error| Error::FileCreationError {
            error,
            path: secret_file_path.clone(),
        })?;
    serde_json::to_writer(file, &account.scrt).map_err(|error| Error::FileWriteError {
        error,
        path: secret_file_path,
    })?;

    // Save the public account
    let mut public_file_path = db_dir.clone();
    public_file_path.push(format!("on-chain/{}_public_account.json", cfg.user));
    let file =
        File::create(public_file_path.clone()).map_err(|error| Error::FileCreationError {
            error,
            path: public_file_path.clone(),
        })?;
    serde_json::to_writer(file, &account.scrt).map_err(|error| Error::FileWriteError {
        error,
        path: public_file_path,
    })?;
    timing!("account.save_output", start, Instant::now());

    Ok(())
}

fn process_destroy_account(user: String, db_dir: Option<PathBuf>) -> Result<(), Error> {
    let start = Instant::now();
    let db_dir = db_dir.ok_or(Error::EmptyDatabaseDir)?;

    let mut secret_file_path = db_dir.clone();
    secret_file_path.push(format!("off-chain/{}_secret_account.json", user));
    std::fs::remove_file(secret_file_path.clone()).map_err(|error| Error::FileRemovalError {
        error,
        path: secret_file_path,
    })?;

    let mut public_file_path = db_dir.clone();
    public_file_path.push(format!("on-chain/{}_public_account.json", user));
    std::fs::remove_file(public_file_path.clone()).map_err(|error| Error::FileRemovalError {
        error,
        path: public_file_path,
    })?;

    timing!("account.remove_account", start, Instant::now());
    Ok(())
}

fn generate_secret_account(rng: &mut StdRng) -> SecAccount {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
        pblc: elg_pub.into(),
        scrt: elg_secret.into(),
    };
    let sign_keys =
        MiniSecretKey::generate_with(rng.clone()).expand_to_keypair(ExpansionMode::Ed25519);

    let asset_id = AssetId::from(1);
    let asset_id_witness = CommitmentWitness::from((asset_id.clone().into(), rng));
    SecAccount {
        enc_keys,
        sign_keys,
        asset_id,
        asset_id_witness,
    }
}
