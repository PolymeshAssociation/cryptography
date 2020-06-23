mod input;

use env_logger;
use input::{parse_input, CLI};
use log::info;
use mercat_common::{
    create_account::process_create_account, errors::Error, init_print_logger, remove_file,
    OFF_CHAIN_DIR, ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE, SECRET_ACCOUNT_FILE,
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
            let seed = cfg.seed.ok_or(Error::EmptySeed).unwrap();
            let db_dir = cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap();
            process_create_account(seed, db_dir, cfg.ticker, cfg.account_id, cfg.user).unwrap()
        }
        CLI::Cleanup { user, db_dir } => process_destroy_account(user, db_dir).unwrap(),
        CLI::CreateFrom { config: _ } => panic!("This should not happen!"),
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
