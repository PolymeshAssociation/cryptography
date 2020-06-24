use crate::{
    chain_setup::process_asset_id_creation, create_account::process_create_account, errors::Error,
    load_object, COMMON_OBJECTS_DIR, OFF_CHAIN_DIR, ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE,
    SECRET_ACCOUNT_FILE,
};
use cryptography::mercat::{PubAccount, SecAccount};
use log::info;
use rand::Rng;
use std::path::PathBuf;
use std::{collections::HashSet, fs, io, path::Path, time::Instant};

pub enum Transaction {
    Transfer(Transfer),
    Fund(Fund),
    Create(Create),
}

pub struct Party {
    pub name: String,
    pub cheater: bool,
}

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

impl Transfer {
    pub fn send(&self) -> String {
        String::from("list of arguments")
    }

    pub fn receive(&self) -> String {
        String::from("list of arguments")
    }

    pub fn mediate(&self) -> Option<String> {
        // since based  on cheating, the transaction might not get to the mediator
        Some(String::from("list of arguments"))
    }

    pub fn validate(&self) -> String {
        String::from("list of arguments")
    }
}

pub struct Create {
    pub id: u32,
    pub account_id: u32,
    pub owner: Party,
    pub mediator: Party,
    pub mediator_approves: bool,
    pub ticker: String,
}

fn cheater_flag(is_cheater: bool) -> String {
    if is_cheater {
        String::from("--cheater")
    } else {
        String::from("")
    }
}

type StepFunc = Box<dyn Fn() -> String>;

impl Create {
    pub fn create_account(&self) -> StepFunc {
        let value = format!(
            "mercat-account create --account-id {} --ticker {} --user {} {}",
            self.account_id,
            self.ticker,
            self.owner.name,
            cheater_flag(self.owner.cheater)
        );
        return Box::new(move || value.clone());
    }

    pub fn validate(&self) -> StepFunc {
        let value = format!("run-validate-function-on --account-id={}", self.account_id);
        return Box::new(move || value.clone());
    }

    pub fn order(&self) -> Vec<StepFunc> {
        vec![self.create_account(), self.validate()]
    }
}

pub struct Fund {
    pub id: u32,
    pub owner: Party,
    pub mediator: Party,
    pub mediator_approves: bool,
    pub ticker: String,
    pub amount: u32,
}

pub enum TransactionMode {
    Sequence {
        repeat: u32,
        steps: Vec<TransactionMode>,
    },
    Concurrent {
        repeat: u32,
        steps: Vec<TransactionMode>,
    },
    Transaction(Transaction),
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

#[derive(PartialEq, Eq, Hash, Debug)]
pub struct Account {
    owner: String,
    ticker: String,
    balance: u32,
}

pub struct TestCase {
    title: String,
    ticker_names: Vec<String>,
    accounts: Vec<Account>,
    /// NOTE: top level transaction is NOT a vector
    transactions: TransactionMode,
    accounts_outcome: HashSet<Account>,
    /// Maximum allowable time in Milliseconds
    timing_limit: u128,
    chain_db_dir: PathBuf,
}

impl TestCase {
    fn run(&self) -> Result<HashSet<Account>, Error> {
        self.chain_setup()?;
        self.make_empty_accounts()?;
        let start = Instant::now();
        //for transaction in self.transaction_sequence() {
        //    transaction.run()?;
        //}
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

    // TODO also generate and log the corresponding commands, in case we need to run them for debugging
    fn make_empty_accounts(&self) -> Result<(), Error> {
        let mut account_id = 0;
        for account in &self.accounts {
            let mut rng = rand::thread_rng();
            let mut seed = [0u8; 32];
            rng.fill(&mut seed);
            let seed = base64::encode(seed);
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
            steps: vec![TransactionMode::Transaction(Transaction::Fund(Fund {
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
