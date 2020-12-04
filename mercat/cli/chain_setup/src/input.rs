use confy;
use log::info;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct CLI {
    /// Space separated list of ticker names.
    #[structopt(short, long, help = "Space separated list of a ticker names.")]
    pub ticker_names: Vec<String>,

    /// The directory that will serve as the database of the on/off-chain data and will be used
    /// to save and load the data that in a real execution would be written to the on/off the
    /// blockchain. Defaults to the current directory. This directory will have two main
    /// sub-directories: `on-chain` and `off-chain`
    #[structopt(
        parse(from_os_str),
        help = "The directory to load and save the input and output files. Defaults to current directory.",
        short,
        long
    )]
    pub db_dir: Option<PathBuf>,
}

pub fn parse_input() -> Result<CLI, confy::ConfyError> {
    info!("Parsing input configuration.");
    let args: CLI = CLI::from_args();
    // Set the default db directory
    let db_dir = args.db_dir.or_else(|| std::env::current_dir().ok());

    Ok(CLI {
        ticker_names: args.ticker_names,
        db_dir,
    })
}
