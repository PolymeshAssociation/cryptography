use confy;
use log::info;
use mercat_common::save_config;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct CreateMediatorAccountInfo {
    /// The name of the mediator.
    /// It is the responsibility of the caller to ensure this name is unique.
    /// If it is not unique the artifacts will be overwritten.
    #[structopt(
        short,
        long,
        help = "The name of the mediator. This name must be unique."
    )]
    pub user: String,

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

    /// An optional seed that can be passed to reproduce a previous run of this CLI.
    /// The seed can be found inside the logs.
    #[structopt(
        short,
        long,
        help = "Base64 encoding of an initial seed. If not provided, the seed will be chosen at random."
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
pub struct IssueAssetInfo {
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

    /// The transaction ID for the asset issuance transaction.
    /// This ID must be the same as the one used to initialize the asset issuance,
    /// using the `mercat-account` CLI.
    #[structopt(long, help = "The id of the transaction. This value must be unique.")]
    pub tx_id: u32,

    /// The name of the issuer.
    /// An account must have already been created for this user, using `mercat-account`
    /// CLI.
    #[structopt(short, long, help = "The name of the user.")]
    pub issuer: String,

    /// The name of the mediator.
    #[structopt(short, long, help = "The name of the user.")]
    pub mediator: String,

    /// An optional seed that can be passed to reproduce a previous run of this CLI.
    /// The seed can be found inside the logs.
    #[structopt(
        short,
        long,
        help = "Base64 encoding of an initial seed. If not provided, the seed will be chosen at random."
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
pub enum CLI {
    /// Create a MERCAT mediator account.
    Create(CreateMediatorAccountInfo),

    /// Justify a MERCAT asset issuance transaction.
    JustifyIssuance(IssueAssetInfo),
}

fn gen_seed() -> String {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    base64::encode(seed)
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

            let cfg = CreateMediatorAccountInfo {
                save_config: cfg.save_config.clone(),
                seed,
                db_dir,
                user: cfg.user.clone(),
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg
            );

            // Save the config is the argument is passed.
            save_config(cfg.save_config.clone(), &cfg);

            return Ok(CLI::Create(cfg));
        }

        CLI::JustifyIssuance(cfg) => {
            // Set the default seed and db_dir if needed.
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let seed: Option<String> = cfg.seed.clone().or_else(|| Some(gen_seed()));
            info!("Seed: {:?}", seed.clone().unwrap());
            let cfg = IssueAssetInfo {
                db_dir,
                tx_id: cfg.tx_id,
                issuer: cfg.issuer,
                mediator: cfg.mediator,
                seed,
                save_config: cfg.save_config.clone(),
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg.clone()
            );

            // Save the config is the argument is passed.
            save_config(cfg.save_config.clone(), &cfg);

            return Ok(CLI::JustifyIssuance(cfg));
        }
    }
}
