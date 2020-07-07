//! A simple commandline application to act as a MERCAT mediator.
//! Use `mercat_mediator --help` to see the usage.
//!

mod input;

use mercat_common::{
    errors::Error,
    init_print_logger,
    justify::{justify_asset_issuance, justify_asset_transaction, process_create_mediator},
};

use env_logger;
use input::{parse_input, CLI};
use log::info;
use metrics::timing;
use std::time::Instant;

fn main() {
    env_logger::init();
    info!("Starting the program.");
    init_print_logger();

    let parse_arg_timer = Instant::now();
    let args = parse_input().unwrap();
    timing!("mediator.argument_parse", parse_arg_timer, Instant::now());

    match args {
        CLI::Create(cfg) => process_create_mediator(
            cfg.seed.ok_or(Error::EmptySeed).unwrap(),
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.user,
        )
        .unwrap(),
        CLI::JustifyIssuance(cfg) => justify_asset_issuance(
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.issuer,
            cfg.mediator,
            cfg.account_id_from_ticker,
            cfg.tx_id,
            cfg.reject,
        )
        .unwrap(),
        CLI::JustifyTransaction(cfg) => justify_asset_transaction(
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.sender,
            cfg.receiver,
            cfg.mediator,
            cfg.ticker,
            cfg.tx_id,
            cfg.reject,
        )
        .unwrap(),
    };

    info!("The program finished successfully.");
}
