//! A simple commandline application to act as a MERCAT auditor.
//! Use `mercat-auditor --help` to see the usage.
//!

mod input;

use mercat_common::{
    audit::{process_audit, process_create_auditor},
    init_print_logger,
};

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
    timing!("auditor.argument_parse", parse_arg_timer, Instant::now());

    match args {
        CLI::Create(cfg) => process_create_auditor(
            cfg.seed.expect("Empty seed!"),
            cfg.db_dir.expect("Empty database directory"),
            cfg.user,
            cfg.user_id,
        )
        .unwrap(),
        CLI::AuditTransaction(cfg) => process_audit(
            cfg.auditor,
            cfg.tx_name,
            cfg.db_dir.expect("Empty database directory"),
        )
        .unwrap(),
    };

    info!("The program finished successfully.");
}
