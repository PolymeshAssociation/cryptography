use crate::{
    chain_setup::process_asset_id_creation, create_account::process_create_account, errors::Error,
    load_object, COMMON_OBJECTS_DIR, OFF_CHAIN_DIR, ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE,
    SECRET_ACCOUNT_FILE,
};
use cryptography::mercat::{PubAccount, SecAccount};
use log::info;
use rand::Rng;
use rand::{rngs::StdRng, SeedableRng};
use std::path::PathBuf;
use std::{collections::HashSet, fs, io, time::Instant};

// --------------------------------------------------------------------------------------------------
// -                                       data types                                                -
// ---------------------------------------------------------------------------------------------------

/// The signature fo the function for a generic step in a transaction. This function performs
/// the action (e.g., initializing a transaction, finalizing a transaction, or creating an account),
/// and returns the corresponding CLI command that can be run to reproduce this step manually.
type StepFunc = Box<dyn Fn() -> String + 'static>;

/// The trait which prescribes the order of functions needed for a transaction. For example, for a
/// confidential transaction, the order is initiate, finalize, mediate, and finally validate.
trait TransactionOrder {
    fn order(&self) -> Vec<StepFunc>;
}

/// Represents the three types of mercat transactions.
pub enum Transaction {
    /// Transfer a balance from Alice to Bob, with some mediator and validator.
    Transfer(Transfer),
    /// Create an account for Alice for a ticker, with balance of zero.
    Create(Create),
    /// Issue tokens for an account (effectively funding an account).
    Issue(Issue),
}

/// A generic party, can be sender, receiver, or mediator.
pub struct Party {
    pub name: String,
    pub cheater: bool,
}

/// Data type of the transaction of transferring balance.
pub struct Transfer {
    pub id: u32,
    pub sender: Party,
    pub receiver: Party,
    pub receiver_approves: bool,
    pub mediator: Party,
    pub mediator_approves: bool,
    pub amount: u32,
    pub ticker: String,
}

/// Data type of the transaction of creating empty account.
pub struct Create {
    pub id: u32,
    pub seed: String,
    pub chain_db_dir: PathBuf,
    pub account_id: u32,
    pub owner: Party,
    pub mediator: Party,
    pub mediator_approves: bool,
    pub ticker: String,
}

/// Data type of the transaction of funding an account by issuer.
pub struct Issue {
    pub id: u32,
    pub owner: Party,
    pub mediator: Party,
    pub mediator_approves: bool,
    pub ticker: String,
    pub amount: u32,
}

/// Human readable form of a mercat account.
#[derive(PartialEq, Eq, Hash, Debug)]
pub struct Account {
    owner: String,
    ticker: String,
    balance: u32,
}

/// Represents the various combinations of the transactions.
pub enum TransactionMode {
    /// The transactions are run `repeat` number of times, and in each iteration, the
    /// steps of one transaction are done before the steps of the next transaction.
    Sequence {
        repeat: u32,
        steps: Vec<TransactionMode>,
    },
    /// The transactions are run `repeat` number of times, and in each iteration, the
    /// steps of the transactions are interleaved randomly.
    Concurrent {
        repeat: u32,
        steps: Vec<TransactionMode>,
    },
    Transaction(Transaction),
}

/// Represents a testcase that is read from the config file.
pub struct TestCase {
    /// Human readable description of the testcase. Will be printed to the log.
    title: String,
    /// The list of valid ticker names. This names will be converted to asset ids for meract.
    ticker_names: Vec<String>,
    /// The initial list of accounts for each party.
    accounts: Vec<Account>,
    /// The transactions of this testcase.
    transactions: TransactionMode,
    /// The expected value of the accounts at the end of the scenario.
    accounts_outcome: HashSet<Account>,
    /// Maximum allowable time in Milliseconds
    timing_limit: u128,
    /// the directory that will act as the chain datastore.
    chain_db_dir: PathBuf,
}

// --------------------------------------------------------------------------------------------------
// -                                  data type methods                                             -
// --------------------------------------------------------------------------------------------------

impl TransactionOrder for Transaction {
    fn order(&self) -> Vec<StepFunc> {
        match self {
            Transaction::Issue(fund) => fund.order(),
            Transaction::Transfer(transfer) => transfer.order(),
            Transaction::Create(create) => create.order(),
        }
    }
}

impl Transfer {
    pub fn send(&self) -> StepFunc {
        let value = format!("todo {}", self.id);
        // TODO: run the initialize transfer function, and return its CLI + args
        //       sea "create_account" function for an example of how it will look like.
        return Box::new(move || value.clone());
    }

    pub fn receive(&self) -> StepFunc {
        let value = format!("todo {}", self.id);
        return Box::new(move || value.clone());
    }

    pub fn mediate(&self) -> StepFunc {
        let value = format!("todo {}", self.id);
        return Box::new(move || value.clone());
    }

    pub fn validate(&self) -> StepFunc {
        let value = format!("todo {}", self.id);
        return Box::new(move || value.clone());
    }

    pub fn order(&self) -> Vec<StepFunc> {
        vec![self.send(), self.receive(), self.mediate(), self.validate()]
    }
}

impl Create {
    pub fn create_account(&self) -> StepFunc {
        let value = format!(
            "mercat-account create --account-id {} --ticker {} --user {} {}",
            self.account_id,
            self.ticker,
            self.owner.name,
            cheater_flag(self.owner.cheater)
        );
        return Box::new(move || {
            // TODO: this does not pass the lifetime checks :(
            //process_create_account(
            //    Some(self.seed),
            //    self.chain_db_dir,
            //    self.ticker,
            //    self.account_id,
            //    self.owner.name,
            //)
            //.unwrap();
            value.clone()
        });
    }

    pub fn validate(&self) -> StepFunc {
        let value = format!("todo --account-id={}", self.account_id);
        return Box::new(move || value.clone());
    }

    pub fn order(&self) -> Vec<StepFunc> {
        vec![self.create_account(), self.validate()]
    }
}

impl Issue {
    pub fn issue(&self) -> StepFunc {
        let value = format!("todo {}", self.id);
        return Box::new(move || value.clone());
    }

    pub fn mediate(&self) -> StepFunc {
        let value = format!("todo {}", self.id);
        return Box::new(move || value.clone());
    }

    pub fn validate(&self) -> StepFunc {
        let value = format!("todo {}", self.id);
        return Box::new(move || value.clone());
    }

    pub fn order(&self) -> Vec<StepFunc> {
        vec![self.issue(), self.mediate(), self.validate()]
    }
}

impl TransactionMode {
    fn sequence(&self) -> Vec<StepFunc> {
        match self {
            TransactionMode::Transaction(transaction) => transaction.order(),
            TransactionMode::Sequence { repeat, steps } => {
                let mut seq: Vec<StepFunc> = vec![];
                for _ in 0..*repeat {
                    for transaction in steps {
                        seq.extend(transaction.sequence());
                    }
                }
                seq
            }
            TransactionMode::Concurrent { repeat, steps } => {
                let mut seqs: &Vec<Vec<StepFunc>> = vec![];
                let mut indices: Vec<usize> = vec![];
                for _ in 0..*repeat {
                    indices.push(0);
                    for transaction in steps {
                        seqs.push(transaction.sequence());
                    }
                }
                // TODO Tie this rng to a global rng whose seed can be set for reproduceablity
                let mut rng = rand::thread_rng();
                let mut seed = [0u8; 32];
                rng.fill(&mut seed);
                info!(
                    "Using seed {:?} for interleaving the transactions.",
                    base64::encode(seed)
                );

                let mut rng = StdRng::from_seed(seed);
                let mut seq: Vec<StepFunc> = vec![];

                while indices.len() != 0 {
                    let next = rng.gen_range(0, indices.len());
                    let index = indices[next];
                    if index >= seqs[next].len() {
                        seqs.remove(next);
                        indices.remove(next);
                        continue;
                    }
                    let next_step: StepFunc = seqs[next][index];
                    seq.push(next_step);
                    indices[next] += 1;
                }
                seq
            }
        }
    }
}

impl TestCase {
    fn run(&self) -> Result<HashSet<Account>, Error> {
        self.chain_setup()?;
        self.make_empty_accounts()?;
        let start = Instant::now();
        for transaction in self.transactions.sequence() {
            transaction();
        }
        let duration = Instant::now() - start;
        if duration.as_millis() > self.timing_limit {
            return Err(Error::TimeLimitExceeded {
                want: self.timing_limit,
                got: duration.as_millis(),
            });
        }
        self.resulting_accounts()
    }

    fn chain_setup(&self) -> Result<(), Error> {
        process_asset_id_creation(self.chain_db_dir.clone(), self.ticker_names.clone())
    }

    fn make_empty_accounts(&self) -> Result<(), Error> {
        let mut account_id = 0;
        for account in &self.accounts {
            let mut rng = rand::thread_rng();
            let mut seed = [0u8; 32];
            rng.fill(&mut seed);
            let seed = base64::encode(seed);
            // TODO: change this into a transaction so that it also logs the CLI and its args.
            process_create_account(
                Some(seed),
                self.chain_db_dir.clone(),
                account.ticker.clone(),
                account_id,
                account.owner.clone(),
            )?;
            account_id += 1;
        }
        Ok(())
    }

    /// Reads the contents of all the accounts from the on-chain directory and decrypts
    /// the balance with the secret account from the off-chain directory.
    fn resulting_accounts(&self) -> Result<HashSet<Account>, Error> {
        let mut accounts: HashSet<Account> = HashSet::new();
        let mut path = self.chain_db_dir.clone();
        path.push(ON_CHAIN_DIR);

        for dir in all_dirs_in_dir(path)? {
            if let Some(user) = dir.file_name().and_then(|user| user.to_str()) {
                if user != COMMON_OBJECTS_DIR {
                    for ticker in self.ticker_names.clone() {
                        let pub_file_name = format!("{}_{}", ticker, PUBLIC_ACCOUNT_FILE);
                        let sec_file_name = format!("{}_{}", ticker, SECRET_ACCOUNT_FILE);

                        let mut path = dir.clone();
                        path.push(pub_file_name.clone());
                        if !path.exists() {
                            continue;
                        }
                        let pub_account: PubAccount = load_object(
                            self.chain_db_dir.clone(),
                            ON_CHAIN_DIR,
                            user,
                            &pub_file_name,
                        )?;
                        let sec_account: SecAccount = load_object(
                            self.chain_db_dir.clone(),
                            OFF_CHAIN_DIR,
                            user,
                            &sec_file_name,
                        )?;
                        let account = cryptography::mercat::Account {
                            pblc: pub_account,
                            scrt: sec_account,
                        };
                        let balance = account.decrypt_balance().unwrap();
                        accounts.insert(Account {
                            owner: String::from(user),
                            ticker,
                            balance,
                        });
                    }
                }
            }
        }
        Ok(accounts)
    }
}

// ------------------------------------------------------------------------------------------
// -                                  Utility functions                                     -
// ------------------------------------------------------------------------------------------
fn cheater_flag(is_cheater: bool) -> String {
    if is_cheater {
        String::from("--cheater")
    } else {
        String::from("")
    }
}

fn all_files_in_dir(dir: PathBuf) -> io::Result<Vec<PathBuf>> {
    let mut files = vec![];
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            files.push(path);
        }
    }
    Ok(files)
}

fn all_dirs_in_dir(dir: PathBuf) -> Result<Vec<PathBuf>, Error> {
    let mut files = vec![];
    for entry in fs::read_dir(dir.clone()).map_err(|error| Error::FileReadError {
        error,
        path: dir.clone(),
    })? {
        let entry = entry.map_err(|error| Error::FileReadError {
            error,
            path: dir.clone(),
        })?;
        let path = entry.path();
        if path.is_dir() {
            files.push(path);
        }
    }
    Ok(files)
}

fn parse_config(path: PathBuf) -> Result<TestCase, Error> {
    // TODO read the file and produce a TestCase. Will do once the input format is finalized.
    let mut accounts_outcome: HashSet<Account> = HashSet::new();
    accounts_outcome.insert(Account {
        owner: String::from("alice"),
        ticker: String::from("ACME"),
        balance: 0,
    });
    accounts_outcome.insert(Account {
        owner: String::from("alice"),
        ticker: String::from("AAPL"),
        balance: 50,
    });
    accounts_outcome.insert(Account {
        owner: String::from("bob"),
        ticker: String::from("ACME"),
        balance: 10,
    });
    accounts_outcome.insert(Account {
        owner: String::from("bob"),
        ticker: String::from("AAPL"),
        balance: 5,
    });
    accounts_outcome.insert(Account {
        owner: String::from("carol"),
        ticker: String::from("ACME"),
        balance: 40,
    });

    let mut chain_db_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    chain_db_dir.push("chain_dir/unittest/node/simple");
    Ok(TestCase {
        title: String::from("Mix of concurrent and sequential test"),
        ticker_names: vec![String::from("AAPL"), String::from("ACME")],
        accounts: vec![
            Account {
                owner: String::from("alice"),
                ticker: String::from("ACME"),
                balance: 0,
            },
            Account {
                owner: String::from("alice"),
                ticker: String::from("AAPL"),
                balance: 0,
            },
            Account {
                owner: String::from("bob"),
                ticker: String::from("ACME"),
                balance: 0,
            },
            Account {
                owner: String::from("bob"),
                ticker: String::from("AAPL"),
                balance: 0,
            },
            Account {
                owner: String::from("carol"),
                ticker: String::from("ACME"),
                balance: 0,
            },
        ],
        transactions: TransactionMode::Concurrent {
            repeat: 1,
            steps: vec![TransactionMode::Transaction(Transaction::Issue(Issue {
                id: 1,
                owner: Party {
                    name: String::from("alice"),
                    cheater: false,
                },
                mediator: Party {
                    name: String::from("mike"),
                    cheater: false,
                },
                mediator_approves: true,
                ticker: String::from("ACME"),
                amount: 50,
            }))],
        },
        accounts_outcome,
        timing_limit: 100,
        chain_db_dir,
    })
}

fn accounts_are_equal(want: &HashSet<Account>, got: &HashSet<Account>) -> bool {
    let intersection: HashSet<_> = want.intersection(&got).collect();
    intersection.len() == want.len() && want.len() == got.len()
}

// This is called from the test and benchmark. Allowing it be unused to silence compiler warnings.
#[allow(unused)]
fn run_from(relative: &str) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    let configs = all_files_in_dir(path).unwrap();
    for config in configs {
        let testcase = &parse_config(config).unwrap();
        // TODO configure the logger and metric to go to a file
        info!("Running test case: {}.", testcase.title);
        let want = &testcase.accounts_outcome;
        let got = &testcase.run().unwrap();
        assert!(
            accounts_are_equal(want, got),
            format!("want: {:#?}, got: {:#?}", want, got)
        );
    }
}

// ------------------------------------------------------------------------------------------------
// -                                            Tests                                             -
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    //use sp_std::prelude::*;

    #[test]
    fn test_on_slow_pc() {
        run_from("scenarios/unittest/pc");
    }

    #[test]
    fn test_on_fast_node() {
        run_from("scenarios/unittest/node");
    }

    #[test] // TODO change this to wasm-test
    fn test_on_wasm() {
        run_from("scenarios/unittest/wasm");
    }
}
