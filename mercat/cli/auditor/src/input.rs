use log::info;
use mercat_common::{gen_seed, save_config};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct CreateAuditorAccountInfo {
    /// The name of the auditor.
    /// It is the responsibility of the caller to ensure this name is unique.
    /// If it is not unique the artifacts will be overwritten.
    #[structopt(
        short,
        long,
        help = "The name of the auditor. This name must be unique."
    )]
    pub user: String,

    /// The id of the auditor.
    /// It is the responsibility of the caller to ensure this id is unique.
    #[structopt(short, long, help = "The auditor's id. This name must be unique.")]
    pub user_id: u8,

    /// The directory that will serve as the database of the on/off-chain data and will be used
    /// to save and load the data that in a real execution would be written to the on/off the
    /// blockchain. Defaults to the current directory. This directory will have two main
    /// sub-directories: `on-chain` and `off-chain`.
    #[structopt(
        parse(from_os_str),
        help = "The directory to load and save the input and output files. Defaults to current directory.",
        short,
        long
    )]
    pub db_dir: Option<PathBuf>,

    /// An optional seed, to feed to the RNG, that can be passed to reproduce a previous run of this CLI.
    /// The seed can be found inside the logs.
    #[structopt(
        short,
        long,
        help = "Base64 encoding of an initial seed for the RNG. If not provided, the seed will be chosen at random."
    )]
    pub seed: Option<String>,

    /// An optional path to save the config used for this experiment.
    #[structopt(
        parse(from_os_str),
        long,
        help = "Path to save the input command line arguments as a config file."
    )]
    pub save_config: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct AuditTransactionInfo {
    /// The directory that will serve as the database of the on/off-chain data and will be used
    /// to save and load the data that in a real execution would be written to the on/off the
    /// blockchain. Defaults to the current directory. This directory will have two main
    /// sub-directories: `on-chain` and `off-chain`.
    #[structopt(
        parse(from_os_str),
        help = "The directory to load and save the input and output files. Defaults to current directory.",
        short,
        long
    )]
    pub db_dir: Option<PathBuf>,

    /// The transaction name.
    /// This name must be the same as the one used in either the initialize the asset issuance,
    /// or the tranfer init.
    #[structopt(long, help = "The name of the transaction. This value must be unique.")]
    pub tx_name: String,

    /// The name of the auditor.
    #[structopt(short, long, help = "The name of the auditor.")]
    pub auditor: String,

    /// An optional path to save the config used for this experiment.
    #[structopt(
        parse(from_os_str),
        long,
        help = "Path to save the input command line arguments as a config file."
    )]
    pub save_config: Option<PathBuf>,

    /// Instructs the CLI to act as a cheater.
    #[structopt(long, help = "Instructs the CLI to act as a cheater.")]
    pub cheat: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub enum CLI {
    /// Create a MERCAT auditor account.
    Create(CreateAuditorAccountInfo),

    /// AuditIa MERCAT transfer transaction.
    AuditTransaction(AuditTransactionInfo),
}

pub fn parse_input() -> Result<CLI, confy::ConfyError> {
    info!("Parsing input configuration.");
    let args: CLI = CLI::from_args();

    match args {
        CLI::Create(cfg) => {
            // Set the default seed and db_dir if needed.
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let seed: Option<String> = cfg.seed.clone().or_else(|| Some(gen_seed()));
            info!("Seed: {:?}", seed.clone().unwrap());

            let cfg = CreateAuditorAccountInfo {
                save_config: cfg.save_config.clone(),
                seed,
                db_dir,
                user: cfg.user,
                user_id: cfg.user_id,
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg
            );

            // Save the config if the argument is passed.
            save_config(cfg.save_config.clone(), &cfg);

            Ok(CLI::Create(cfg))
        }

        CLI::AuditTransaction(cfg) => {
            // Set the default seed and db_dir if needed.
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let cfg = AuditTransactionInfo {
                db_dir,
                tx_name: cfg.tx_name,
                auditor: cfg.auditor,
                save_config: cfg.save_config.clone(),
                cheat: cfg.cheat,
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg
            );

            // Save the config if the argument is passed.
            save_config(cfg.save_config.clone(), &cfg);

            Ok(CLI::AuditTransaction(cfg))
        }
    }
}
