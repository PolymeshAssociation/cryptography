use confy;
use log::{debug, info};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, Serialize, Deserialize, StructOpt)]
pub struct AccountGenInfo {
    /// The name of the user. The name can be any valid string that can be used as a file name.
    /// It is the responsibility of the caller to ensure the uniqueness of the name. The CLI
    /// will through an error if the files corresponding to that user name already exist.
    #[structopt(short, long, help = "The name of the user. This name must be unique.")]
    user: String,

    /// The directory that will serve as the chain and will be used to save and load the data
    /// that in a real execution would be written to the blockchain. Defaults to the current
    /// directory.
    #[structopt(
        parse(from_os_str),
        help = "The directory to load and save the input and output files. Defaults to current directory.",
        short,
        long
    )]
    chain_dir: Option<PathBuf>,

    /// The file inside the blockchain directory that contains the global list of asset lists.
    #[structopt(
        parse(from_os_str),
        short,
        long,
        help = "The path to the file, containing the list of valid asset ids."
    )]
    valid_asset_ids_path: PathBuf,

    /// Account id. It is the responsibility of the caller to ensure the uniqueness of the id.
    /// The CLI will not through any error if a duplicate id is passed.
    #[structopt(
        short,
        long,
        help = "The id of the account. This value must be unique."
    )]
    account_id: u32,

    /// An optional seed that can be passed to reproduce a previous run of this CLI.
    /// The seed can be found inside the logs.
    #[structopt(
        short,
        long,
        help = "Base64 encoding of an initial seed. If not provided, the seed will be chosen at random."
    )]
    seed: Option<String>,

    /// An optional flag that determines if the input arguments should be saved in a config file.
    #[structopt(
        parse(from_os_str),
        long,
        help = "Whether to save the input command line arguments in the config file."
    )]
    save_config: Option<PathBuf>,

    /// The path to the config file. This option is mutually exclusive with the rest of the the options.
    #[structopt(
        parse(from_os_str),
        help = "The path to the toml config file. If this option is used, other input options are ignored.",
        long
    )]
    loag_config: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize, StructOpt)]
pub enum CLI {
    /// Create a MERCAT account
    Create(AccountGenInfo),

    /// Remove a previously generated MERCAT account.
    Destroy {
        /// The name of the user whose account will be removed.
        #[structopt(short, long, help = "The name of the user.")]
        user: String,

        /// The directory that will serve as the chain and will be used to save and load the data
        /// that in a real execution would be written to the blockchain. Defaults to the current
        /// directory.
        #[structopt(
            parse(from_os_str),
            help = "The directory to load and save the input and output files. Defaults to current directory.",
            short,
            long
        )]
        chain_dir: Option<PathBuf>,
    },
}

fn with_defaults(args: CLI) -> CLI {
    match &args {
        CLI::Create(cfg) => {
            let chain_dir = cfg
                .chain_dir
                .clone()
                .or_else(|| std::env::current_dir().ok());
            let mut rng = rand::thread_rng();
            let seed: Option<String> = cfg
                .seed
                .clone()
                .or_else(|| Some(base64::encode([rng.gen::<u8>()])));
            debug!("seed: {:?}, chain_dir: {:?}", seed, chain_dir);
            CLI::Create(AccountGenInfo {
                loag_config: cfg.loag_config.clone(),
                save_config: cfg.save_config.clone(),
                seed,
                account_id: cfg.account_id,
                valid_asset_ids_path: cfg.valid_asset_ids_path.clone(),
                chain_dir,
                user: cfg.user.clone(),
            })
        }
        CLI::Destroy { user, chain_dir } => {
            let chain_dir = chain_dir.clone().or_else(|| std::env::current_dir().ok());
            debug!("{:?}", chain_dir);
            CLI::Destroy {
                user: user.clone(),
                chain_dir,
            }
        }
    }
}

pub fn parse_input() -> Result<CLI, confy::ConfyError> {
    info!("Parsing input configuration.");
    let args: CLI = CLI::from_args();

    if let CLI::Create(cfg) = &args {
        match &cfg.loag_config {
            Some(path) => {
                let json_file_content = std::fs::read_to_string(&path).expect(&format!(
                    "Failed to read the account config from file: {:?}.",
                    path
                ));

                let cfg = serde_json::from_str(&json_file_content).unwrap_or_else(|error| {
                    panic!("Failed to deserialize the account config: {}", error)
                });

                info!("Read the following config from {:?}:\n{:#?}", &path, &cfg);
                return Ok(CLI::Create(cfg)); // ignore other arguments and return the loaded config
            }
            None => {}
        };

        if let Some(path) = &cfg.save_config {
            info!("Saving the following config to {:?}:\n{:#?}", &path, &cfg);
            std::fs::write(
                path,
                serde_json::to_string(&cfg).unwrap_or_else(|error| {
                    panic!("Failed to serialize configuration file: {}", error)
                }),
            )
            .expect(&format!(
                "Failed to write the configuration to the file {:?}.",
                path
            ));
        }

        info!(
            "Parsed the following config from the command line:\n{:#?}",
            cfg
        );
        return Ok(with_defaults(args));
    }

    info!(
        "Parsed the following config from the command line:\n{:#?}",
        args
    );

    Ok(with_defaults(args))
}
