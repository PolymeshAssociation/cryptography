//! A simple commandline application to act as a MERCAT account.
//! Use `mercat_account --help` to see the usage.

mod input;

use input::{parse_input, CLI};
use log::info;
use mercat_common::{
    account_create::process_create_account,
    account_issue::process_issue_asset,
    account_transfer::{process_create_tx, process_finalize_tx},
    debug_decrypt_account_balance,
    errors::Error,
    init_print_logger,
};
use metrics::timing;
use std::time::Instant;

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
            process_create_account(
                cfg.seed, db_dir, cfg.ticker, cfg.user, cfg.stdout, cfg.tx_id,
            )
            .unwrap()
        }
        CLI::CreateFrom { config: _ } => panic!("This should not be called directly!"),
        CLI::Decrypt(cfg) => info!(
            "Account balance: {}",
            debug_decrypt_account_balance(
                cfg.user,
                cfg.ticker,
                cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap()
            )
            .unwrap()
        ),
        CLI::Issue(cfg) => process_issue_asset(
            cfg.seed.ok_or(Error::EmptySeed).unwrap(),
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.issuer,
            cfg.account_id_from_ticker,
            cfg.amount,
            cfg.stdout,
            cfg.tx_id,
            cfg.cheat,
        )
        .map(drop)
        .unwrap(),
        CLI::CreateTransaction(cfg) => process_create_tx(
            cfg.seed.ok_or(Error::EmptySeed).unwrap(),
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.sender,
            cfg.receiver,
            cfg.mediator,
            cfg.account_id_from_ticker,
            cfg.amount,
            cfg.stdout,
            cfg.tx_id,
            cfg.cheat,
        )
        .unwrap(),
        CLI::FinalizeTransaction(cfg) => process_finalize_tx(
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.sender,
            cfg.receiver,
            cfg.account_id_from_ticker,
            cfg.amount,
            cfg.stdout,
            cfg.tx_id,
            cfg.cheat,
        )
        .unwrap(),
    };
    info!("The program finished successfully.");
}
