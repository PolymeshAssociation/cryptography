//! A simple commandline application to act as a MERCAT account.
//! Use `mercat_account --help` to see the usage.
//!

mod input;

use codec::{Decode, Encode};
use cryptography::mercat::{
    asset::CtxIssuer, conf_tx::CtxReceiver, conf_tx::CtxSender, Account, AccountMemo,
    AssetTransactionIssuer, ConfidentialTransactionSender, ConfidentialTxState, PubAccount,
    PubInitConfidentialTxData, SecAccount, TxSubstate,
};
use env_logger;
use input::{parse_input, CLI};
use log::info;
use mercat_common::{
    asset_transaction_file, confidential_transaction_file, construct_path,
    create_account::process_create_account, create_rng_from_seed, errors::Error, init_print_logger,
    load_object, remove_file, save_object, CTXInstruction, Instruction, OFF_CHAIN_DIR,
    ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE, SECRET_ACCOUNT_FILE, VALIDATED_PUBLIC_ACCOUNT_FILE,
};
use metrics::timing;
use std::{path::PathBuf, time::Instant};

fn main() {
    env_logger::init();
    info!("Starting the program.");
    init_print_logger();

    let parse_arg_timer = Instant::now();
    let args = parse_input();
    timing!("account.argument_parse", parse_arg_timer, Instant::now());

    match args {
        CLI::Create(cfg) => {
            let db_dir = cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap();
            process_create_account(cfg.seed, db_dir, cfg.ticker, cfg.account_id, cfg.user).unwrap()
        }
        CLI::Cleanup { user, db_dir } => process_destroy_account(user, db_dir).unwrap(),
        CLI::CreateFrom { config: _ } => panic!("This should not happen!"),
        CLI::Issue(cfg) => process_issue_asset(cfg).unwrap(),
        CLI::CreateTransaction(cfg) => process_create_tx(cfg).unwrap(),
        CLI::FinalizeTransaction(cfg) => process_finalize_tx(cfg).unwrap(),
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

    timing!(
        "account.issue_asset.load_from_file",
        load_from_file_timer,
        Instant::now()
    );

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

    timing!(
        "account.issue_asset.init",
        issuance_init_timer,
        Instant::now()
    );

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
        &asset_transaction_file(cfg.tx_id, state),
        &instruction,
    )?;

    timing!(
        "account.issue_asset.save_to_file",
        save_to_file_timer,
        Instant::now()
    );

    Ok(())
}

fn process_create_tx(cfg: input::CreateTransactionInfo) -> Result<(), Error> {
    // Setup the rng.
    let mut rng = create_rng_from_seed(cfg.seed)?;

    // Load sender's secret account and mediator's public credentials from file.
    let db_dir = cfg.db_dir.ok_or(Error::EmptyDatabaseDir)?;
    let load_from_file_timer = Instant::now();

    let sender_account = Account {
        scrt: load_object(
            db_dir.clone(),
            OFF_CHAIN_DIR,
            &cfg.sender,
            SECRET_ACCOUNT_FILE,
        )?,
        pblc: load_object(
            db_dir.clone(),
            ON_CHAIN_DIR,
            &cfg.sender,
            VALIDATED_PUBLIC_ACCOUNT_FILE,
        )?,
    };

    let receiver_account: PubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &cfg.receiver,
        PUBLIC_ACCOUNT_FILE,
    )?;

    let mediator_account: AccountMemo = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &cfg.mediator,
        PUBLIC_ACCOUNT_FILE,
    )?;

    timing!(
        "account.create_tx.load_from_file",
        load_from_file_timer,
        Instant::now()
    );

    // Initialize the transaction.
    let create_tx_timer = Instant::now();
    let sender = CtxSender {};
    let (asset_tx, state) = sender
        .create_transaction(
            &sender_account,
            &receiver_account,
            &mediator_account.owner_enc_pub_key,
            cfg.amount,
            &mut rng,
        )
        .map_err(|error| Error::LibraryError { error })?;
    timing!("account.create_tx.create", create_tx_timer, Instant::now());

    // Save the artifacts to file.
    let save_to_file_timer = Instant::now();
    let instruction = CTXInstruction {
        state,
        data: asset_tx.encode().to_vec(),
    };

    // TODO(CRYP-110)
    // We should name the transactions based on the ordering counters, or we may decide that
    // a global counter (tx_id) is enough and put all transactions inside a common folder.
    save_object(
        db_dir,
        ON_CHAIN_DIR,
        &cfg.sender,
        &confidential_transaction_file(cfg.tx_id, state),
        &instruction,
    )?;

    timing!(
        "account.create_tx.save_to_file",
        save_to_file_timer,
        Instant::now()
    );

    Ok(())
}

fn process_finalize_tx(cfg: input::FinalizeTransactionInfo) -> Result<(), Error> {
    // Setup the rng.
    let mut rng = create_rng_from_seed(cfg.clone().seed)?;

    // Load receiver's secret account and mediator's public credentials from file.
    let db_dir = cfg.clone().db_dir.ok_or(Error::EmptyDatabaseDir)?;
    let load_from_file_timer = Instant::now();

    let receiver_account = Account {
        scrt: load_object(
            db_dir.clone(),
            OFF_CHAIN_DIR,
            &cfg.receiver,
            SECRET_ACCOUNT_FILE,
        )?,
        pblc: load_object(
            db_dir.clone(),
            ON_CHAIN_DIR,
            &cfg.receiver,
            PUBLIC_ACCOUNT_FILE,
        )?,
    };

    let instruction: Instruction = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &cfg.sender,
        &confidential_transaction_file(
            cfg.tx_id.clone(),
            ConfidentialTxState::Initialization(TxSubstate::Validated),
        ),
    )?;

    let tx = PubInitConfidentialTxData::decode(&mut &instruction.data[..]).map_err(|error| {
        Error::ObjectLoadError {
            error,
            path: construct_path(
                db_dir.clone(),
                ON_CHAIN_DIR,
                &cfg.sender.clone(),
                PUBLIC_ACCOUNT_FILE,
            ),
        }
    })?;

    timing!(
        "account.finalize_tx.load_from_file",
        load_from_file_timer,
        Instant::now()
    );

    // Finalize the transaction.
    let finalize_by_receiver_timer = Instant::now();
    let receiver = CtxReceiver {};
    let (asset_tx, state) = receiver
        .finalize_by_receiver(
            tx,
            receiver_account,
            ConfidentialTxState::Initialization(TxSubstate::Validated),
            cfg.amount,
            &mut rng,
        )
        .map_err(|error| Error::LibraryError { error })?;

    timing!(
        "account.finalize_tx.finalize_by_receiver",
        finalize_by_receiver_timer,
        Instant::now()
    );

    // Save the artifacts to file.
    let save_to_file_timer = Instant::now();
    let instruction = CTXInstruction {
        state,
        data: asset_tx.encode().to_vec(),
    };

    // TODO(CRYP-110)
    // We should name the transactions based on the ordering counters, or we may decide that
    // a global counter (tx_id) is enough and put all transactions inside a common folder.
    save_object(
        db_dir,
        ON_CHAIN_DIR,
        &cfg.sender,
        &confidential_transaction_file(cfg.tx_id, state),
        &instruction,
    )?;

    timing!(
        "account.finalize_tx.save_to_file",
        save_to_file_timer,
        Instant::now()
    );

    Ok(())
}
