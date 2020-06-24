//! A simple commandline application to act as a MERCAT account.
//! Use `mercat_account --help` to see the usage.
//!

mod input;

use codec::Encode;
use cryptography::mercat::{asset::CtxIssuer, AccountMemo, AssetTransactionIssuer, SecAccount};
use env_logger;
use input::{parse_input, CLI};
use log::info;
use mercat_common::{
    create_account::process_create_account, create_rng_from_seed, errors::Error, init_print_logger,
    load_object, remove_file, save_object, transaction_file, Instruction, OFF_CHAIN_DIR,
    ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE, SECRET_ACCOUNT_FILE,
};
use metrics::timing;
use std::{path::PathBuf, time::Instant};

fn main() {
    info!("Starting the program.");
    env_logger::init();
    init_print_logger();

    let parse_arg_timer = Instant::now();
    let args = parse_input().unwrap();
    timing!("account.argument_parse", parse_arg_timer, Instant::now());

    match args {
        CLI::Create(cfg) => {
            let db_dir = cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap();
            process_create_account(cfg.seed, db_dir, cfg.ticker, cfg.account_id, cfg.user).unwrap()
        }
        CLI::Cleanup { user, db_dir } => process_destroy_account(user, db_dir).unwrap(),
        CLI::CreateFrom { config: _ } => panic!("This should not happen!"),
        CLI::Issue(cfg) => process_issue_asset(cfg).unwrap(),
    };
    info!("The program finished successfully.");
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
