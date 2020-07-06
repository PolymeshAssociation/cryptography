mod input;
use env_logger;
use input::parse_input;
use log::info;
use metrics::timing;
use std::time::Instant;

fn main() {
    env_logger::init();
    info!("Starting the program.");
    // init_print_logger();

    let parse_arg_timer = Instant::now();
    timing!("validator.argument_parse", parse_arg_timer, Instant::now());

    // match args {
    //     CLI::ValidateIssuance(cfg) => validate_asset_issuance(cfg).unwrap(),
    //     CLI::ValidateAccount(cfg) => validate_account(cfg).unwrap(),
    //     CLI::ValidateTransaction(cfg) => validate_transaction(cfg).unwrap(),
    // };

    info!("The program finished successfully.");
}

/*//! A simple commandline application to act as a MERCAT Validator.
//! Use `mercat_validator --help` to see the usage.

mod input;
use env_logger;
use input::{parse_input, CLI};
use log::info;
use mercat_common::{
    errors::Error,
    init_print_logger,
    validate::{validate_account, validate_asset_issuance, validate_transaction},
};
use metrics::timing;
use std::time::Instant;

fn main() {
    env_logger::init();
    info!("Starting the program.");
    init_print_logger();

    let parse_arg_timer = Instant::now();
    let args = parse_input().unwrap();
    timing!("validator.argument_parse", parse_arg_timer, Instant::now());

    match args {
        CLI::ValidateIssuance(cfg) => validate_asset_issuance(
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.issuer,
            cfg.mediator,
            cfg.state,
            cfg.tx_id,
            cfg.account_id_from_ticker,
        )
        .unwrap(),
        CLI::ValidateAccount(cfg) => validate_account(
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.user,
            cfg.ticker,
        )
        .unwrap(),
        CLI::ValidateTransaction(cfg) => validate_transaction(
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.sender,
            cfg.receiver,
            cfg.mediator,
            cfg.state,
            cfg.tx_id,
            cfg.account_id_from_ticker,
        )
        .unwrap(),
    };

    info!("The program finished successfully.");
}
*/
