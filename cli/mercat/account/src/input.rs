use confy;
use log::info;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct AccountGenInfo {
    /// The name of the user. The name can be any valid string that can be used as a file name.
    /// It is the responsibility of the caller to ensure the uniqueness of the name.
    #[structopt(short, long, help = "The name of the user. This name must be unique.")]
    pub user: String,

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

    /// Account id. It is the responsibility of the caller to ensure the uniqueness of the id.
    /// The CLI will not throw any error if a duplicate id is passed.
    #[structopt(
        short,
        long,
        help = "The id of the account. This value must be unique."
    )]
    pub account_id: u32,

    /// Asset id. An asset ticker name which is a string of at most 12 characters.
    #[structopt(
        short,
        long,
        help = "The asset ticker name. String of at most 12 characters."
    )]
    pub ticker: String,

    /// An optional seed that can be passed to reproduce a previous run of this CLI.
    /// The seed can be found inside the logs.
    #[structopt(
        short,
        long,
        help = "Base64 encoding of an initial seed. If not provided, the seed will be chosen at random."
    )]
    pub seed: Option<String>,

    /// An optional flag that determines if the input arguments should be saved in a config file.
    #[structopt(
        parse(from_os_str),
        long,
        help = "Whether to save the input command line arguments in the config file."
    )]
    pub save_config: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub enum CLI {
    /// Create a MERCAT account using command line arguments.
    Create(AccountGenInfo),

    /// Create a MERCAT account from a config file.
    CreateFrom {
        /// The path to the config file. This is a positional argument.
        config: PathBuf,
    },

    /// Remove a previously generated MERCAT account.
    Cleanup {
        /// The name of the user whose account will be removed.
        #[structopt(short, long, help = "The name of the user.")]
        user: String,

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
        db_dir: Option<PathBuf>,
    },
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
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let seed: Option<String> = cfg.seed.clone().or_else(|| Some(gen_seed()));
            info!("Seed: {:?}", seed.clone().unwrap()); // unwrap won't panic

            let cfg = AccountGenInfo {
                save_config: cfg.save_config.clone(),
                seed,
                account_id: cfg.account_id,
                ticker: cfg.ticker,
                db_dir,
                user: cfg.user.clone(),
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg
            );

            // Save the config is the argument is passed
            if let Some(path) = &cfg.save_config {
                info!("Saving the following config to {:?}:\n{:#?}", &path, &cfg);
                std::fs::write(
                    path,
                    serde_json::to_string_pretty(&cfg).unwrap_or_else(|error| {
                        panic!("Failed to serialize configuration file: {}", error)
                    }),
                )
                .expect(&format!(
                    "Failed to write the configuration to the file {:?}.",
                    path
                ));
            }

            return Ok(CLI::Create(cfg));
        }
        CLI::CreateFrom { config } => {
            let json_file_content = std::fs::read_to_string(&config).expect(&format!(
                "Failed to read the account config from file: {:?}.",
                config
            ));

            let cfg = serde_json::from_str(&json_file_content).unwrap_or_else(|error| {
                panic!("Failed to deserialize the account config: {}", error)
            });

            info!("Read the following config from {:?}:\n{:#?}", &config, &cfg);
            return Ok(CLI::Create(cfg));
        }
        CLI::Cleanup { user, db_dir } => {
            // Set the default directory for db_dir
            let db_dir = db_dir.clone().or_else(|| std::env::current_dir().ok());
            let args = CLI::Cleanup {
                user: user.clone(),
                db_dir,
            };
            info!(
                "Parsed the following config from the command line:\n{:#?}",
                args
            );
            return Ok(args);
        }
    }
}
