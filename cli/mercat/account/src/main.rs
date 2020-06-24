//! A simple commandline application to act as a MERCAT account.
//! Use `mercat_account --help` to see the usage.
//!

mod input;

use codec::Encode;
use cryptography::{
    asset_id_from_ticker,
    asset_proofs::{CommitmentWitness, ElgamalSecretKey},
    mercat::{
        account::create_account, asset::CtxIssuer, AccountMemo, AssetTransactionIssuer,
        EncryptionKeys, SecAccount,
    },
};
use curve25519_dalek::scalar::Scalar;
use env_logger;
use input::{parse_input, CLI};
use log::info;
use mercat_common::{
    create_rng_from_seed, errors::Error, get_asset_ids, init_print_logger, load_object,
    remove_file, save_object, transaction_file, Instruction, OFF_CHAIN_DIR, ON_CHAIN_DIR,
    PUBLIC_ACCOUNT_FILE, SECRET_ACCOUNT_FILE,
};
use metrics::timing;
use rand::{CryptoRng, RngCore};
use schnorrkel::{ExpansionMode, MiniSecretKey};
use std::{path::PathBuf, time::Instant};

fn main() {
    info!("Starting the program.");
    env_logger::init();
    init_print_logger();

    let parse_arg_timer = Instant::now();
    let args = parse_input().unwrap();
    timing!("account.argument_parse", parse_arg_timer, Instant::now());

    match args {
        CLI::Create(cfg) => process_create_account(cfg).unwrap(),
        CLI::Cleanup { user, db_dir } => process_destroy_account(user, db_dir).unwrap(),
        CLI::CreateFrom { config: _ } => panic!("This should not happen!"),
        CLI::Issue(cfg) => process_issue_asset(cfg).unwrap(),
    };
    info!("The program finished successfully.");
}

fn process_create_account(cfg: input::CreateAccountInfo) -> Result<(), Error> {
    // Setup the rng.
    let mut rng = create_rng_from_seed(cfg.seed)?;

    // Create the account.
    let db_dir = cfg.db_dir.ok_or(Error::EmptyDatabaseDir)?;
    let secret_account = create_secret_account(&mut rng, cfg.ticker_id)?;
    let valid_asset_ids = get_asset_ids(db_dir.clone())?;

    let create_account_timer = Instant::now();
    let account = create_account(secret_account, &valid_asset_ids, cfg.account_id, &mut rng)
        .map_err(|error| Error::LibraryError { error })?;
    timing!("account.call_library", create_account_timer, Instant::now());

    // Save the artifacts to file.
    let save_to_file_timer = Instant::now();
    save_object(
        db_dir.clone(),
        OFF_CHAIN_DIR,
        &cfg.user,
        SECRET_ACCOUNT_FILE,
        &account.scrt,
    )?;

    save_object(
        db_dir,
        ON_CHAIN_DIR,
        &cfg.user,
        PUBLIC_ACCOUNT_FILE,
        &account.pblc,
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

fn process_issue_asset(cfg: input::IssueAssetInfo) -> Result<(), Error> {
    // Setup the rng.
    let mut rng = create_rng_from_seed(cfg.seed)?;

    // Load issuer's secret account and mediator's public credentials from file.
    let db_dir = cfg.db_dir.ok_or(Error::EmptyDatabaseDir)?;
    let load_from_file_timer = Instant::now();

    let issuer_account: SecAccount = load_object(
        db_dir.clone(),
        OFF_CHAIN_DIR,
        &cfg.issuer,
        SECRET_ACCOUNT_FILE,
    )?;

    let mediator_account: AccountMemo = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &cfg.mediator,
        PUBLIC_ACCOUNT_FILE,
    )?;

    timing!("account.issue_asset", load_from_file_timer, Instant::now());

    // Initialize the asset issuance process.
    let issuance_init_timer = Instant::now();
    let issuer = CtxIssuer {};
    let (asset_tx, state) = issuer
        .initialize(
            cfg.account_id,
            &issuer_account,
            &mediator_account.owner_enc_pub_key,
            cfg.amount,
            &mut rng,
        )
        .map_err(|error| Error::LibraryError { error })?;

    timing!("account.issue_asset", issuance_init_timer, Instant::now());

    // Save the artifacts to file.
    let save_to_file_timer = Instant::now();
    let instruction = Instruction {
        state,
        data: asset_tx.encode().to_vec(),
    };

    save_object(
        db_dir,
        ON_CHAIN_DIR,
        &cfg.issuer,
        &transaction_file(cfg.tx_id, state),
        &instruction,
    )?;

    timing!("account.issue_asset", save_to_file_timer, Instant::now());

    Ok(())
}
