use crate::{
    account_create_transaction_file, all_unverified_tx_files, asset_transaction_file,
    compute_enc_pending_balance, confidential_transaction_file, debug_decrypt, errors::Error,
    get_user_ticker_from, last_ordering_state, load_object, load_tx_file, parse_tx_name,
    save_object, save_to_file, user_public_account_balance_file, user_public_account_file,
    AssetInstruction, CoreTransaction, Direction, OrderedPubAccount, OrderedPubAccountTx,
    PrintableAccountId, TransferInstruction, ValidationResult, COMMON_OBJECTS_DIR,
    LAST_VALIDATED_TX_ID_FILE, OFF_CHAIN_DIR, ON_CHAIN_DIR,
};
use codec::{Decode, Encode};
use confidential_identity_core::asset_proofs::AssetId;
use log::{debug, error, info};
use mercat::{
    account::AccountValidator, asset::AssetValidator, transaction::TransactionValidator,
    AccountCreatorVerifier, AssetTransactionVerifier, AssetTxState, EncryptedAmount,
    FinalizedTransferTx, InitializedAssetTx, InitializedTransferTx, PubAccount,
    TransferTransactionVerifier, TransferTxState, TxSubstate,
};
use metrics::timing;
use rand::rngs::OsRng;
use std::{collections::HashSet, path::PathBuf, time::Instant};

fn load_all_unverified_and_ready(db_dir: PathBuf) -> Result<Vec<CoreTransaction>, Error> {
    all_unverified_tx_files(db_dir)?
        .into_iter()
        .map(parse_tx_name)
        .map(|res| match res {
            Err(error) => Err(error),
            Ok((tx_id, user, state, tx_file_path)) => {
                load_tx_file(tx_id, user, state, tx_file_path)
            }
        })
        .filter(|res| res.is_err() || res.as_ref().unwrap().is_ready_for_validation())
        .collect()
}

pub fn validate_all_pending(db_dir: PathBuf) -> Result<(), Error> {
    // TODO: This function should be called when any justify is called. To be fixed in CRYP-131.
    let all_unverified_and_ready = load_all_unverified_and_ready(db_dir.clone())?;
    let mut last_tx_id: Option<u32> = None;

    let mut results: Vec<ValidationResult> = vec![];
    // For each of them call the validate function and process as needed
    for tx in all_unverified_and_ready {
        match tx {
            CoreTransaction::IssueInit {
                issue_tx,
                tx_id,
                issuer: _,
                ordering_state: _,
                amount,
            } => {
                let result =
                    validate_asset_issuance(db_dir.clone(), amount, issue_tx.clone(), tx_id);
                results.push(result);
                last_tx_id = Some(std::cmp::max(last_tx_id.unwrap_or_default(), tx_id));
            }
            CoreTransaction::TransferJustify {
                init_tx,
                finalized_tx,
                tx_id,
                mediator,
            } => {
                let asset_id = init_tx.memo.sender_account.asset_id;
                let (sender, ticker, _) = get_user_ticker_from(asset_id, db_dir.clone())?;
                let sender_ordered_pub_account: OrderedPubAccount = load_object(
                    db_dir.clone(),
                    ON_CHAIN_DIR,
                    &sender,
                    &user_public_account_file(&ticker),
                )?;
                let sender_account_balance: EncryptedAmount = load_object(
                    db_dir.clone(),
                    ON_CHAIN_DIR,
                    &sender,
                    &user_public_account_balance_file(&ticker),
                )?;
                let ordering_state = last_ordering_state(
                    sender.clone(),
                    sender_ordered_pub_account.last_processed_tx_counter,
                    tx_id,
                    db_dir.clone(),
                )?;
                let pending_balance = compute_enc_pending_balance(
                    &sender,
                    ordering_state,
                    sender_ordered_pub_account.last_processed_tx_counter,
                    sender_account_balance,
                    db_dir.clone(),
                )?;
                debug!(
                    "------------> validating tx: {}, pending transfer balance: {}",
                    tx_id,
                    debug_decrypt(asset_id, pending_balance, db_dir.clone())?
                );
                let (sender_result, receiver_result) = validate_transaction(
                    db_dir.clone(),
                    init_tx,
                    finalized_tx,
                    mediator,
                    pending_balance,
                    tx_id,
                );
                results.push(sender_result);
                results.push(receiver_result);
                last_tx_id = Some(std::cmp::max(last_tx_id.unwrap_or_default(), tx_id));
            }
            CoreTransaction::Account {
                account_tx,
                tx_id,
                ordering_state: _,
            } => {
                if let Err(error) =
                    validate_account(db_dir.clone(), account_tx.pub_account.asset_id)
                {
                    error!("Error in validation of tx-{}: {:#?}", tx_id, error);
                    error!("tx-{}: Ignoring the validation error and continuing the with rest of the validations.", tx_id);
                }
                last_tx_id = Some(std::cmp::max(last_tx_id.unwrap_or_default(), tx_id));
            }
            _ => {
                return Err(Error::TransactionIsNotReadyForValidation);
            }
        }
    }

    // TODO: CRYP-134, use a more elegant way of writing the following code.

    // find all users
    let mut users: Vec<String> = vec![];
    for result in results.clone() {
        if result.user != "n/a" {
            users.push(result.user);
        }
    }
    // find all accounts
    let mut accounts: HashSet<(String, String)> = HashSet::new();
    for user in users {
        for result in results.clone() {
            if result.user == user {
                accounts.insert((result.user, result.ticker));
            }
        }
    }

    for (user, ticker) in accounts.clone() {
        let ordered_pub_account: OrderedPubAccount = load_object(
            db_dir.clone(),
            ON_CHAIN_DIR,
            &user,
            &user_public_account_file(&ticker),
        )?;
        let mut new_balance: EncryptedAmount = load_object(
            db_dir.clone(),
            ON_CHAIN_DIR,
            &user,
            &user_public_account_balance_file(&ticker),
        )?;
        debug!(
            "------------> Validation complete, updating {}-{}. Starting balance: {}",
            &user,
            &ticker,
            debug_decrypt(
                ordered_pub_account.pub_account.asset_id,
                new_balance,
                db_dir.clone()
            )?
        );
        for result in results.clone() {
            if result.user == user && result.ticker == ticker {
                match result.direction {
                    Direction::Incoming => {
                        if let Some(amount) = result.amount {
                            debug!(
                                "---------------------> updating {}-{} increasing by {}",
                                &user,
                                &ticker,
                                debug_decrypt(
                                    ordered_pub_account.pub_account.asset_id,
                                    amount,
                                    db_dir.clone()
                                )?
                            );
                            new_balance += amount;
                        } else {
                            // based on the reason and the strategy, we can break the loop or ignore
                            // TODO: add strategy selection to the config. CRYP-132
                        }
                    }
                    Direction::Outgoing => {
                        if let Some(amount) = result.amount {
                            debug!(
                                "---------------------> updating {}-{} decreasing by {}",
                                &user,
                                &ticker,
                                debug_decrypt(
                                    ordered_pub_account.pub_account.asset_id,
                                    amount,
                                    db_dir.clone()
                                )?
                            );
                            new_balance -= amount;
                        } else {
                            // based on the reason and the strategy, we can break the loop or ignore
                        }
                    }
                }
            }
        }

        save_object(
            db_dir.clone(),
            ON_CHAIN_DIR,
            &user,
            &user_public_account_file(&ticker),
            &OrderedPubAccount {
                last_processed_tx_counter: last_tx_id,
                pub_account: PubAccount {
                    asset_id: ordered_pub_account.pub_account.asset_id,
                    owner_enc_pub_key: ordered_pub_account.pub_account.owner_enc_pub_key,
                },
            },
        )?;
        save_object(
            db_dir.clone(),
            ON_CHAIN_DIR,
            &user,
            &user_public_account_balance_file(&ticker),
            &new_balance,
        )?;
    }

    save_to_file(
        db_dir,
        OFF_CHAIN_DIR,
        COMMON_OBJECTS_DIR,
        LAST_VALIDATED_TX_ID_FILE,
        &last_tx_id,
    )?;
    Ok(())
}

pub fn validate_asset_issuance(
    db_dir: PathBuf,
    amount: u32,
    asset_tx: InitializedAssetTx,
    tx_id: u32,
) -> ValidationResult {
    let load_objects_timer = Instant::now();

    let issuer_asset_id = asset_tx.account.asset_id;
    let res = get_user_ticker_from(issuer_asset_id, db_dir.clone());
    if let Err(error) = res {
        error!("Error in validation of tx-{}: {:#?}", tx_id, error);
        return ValidationResult::error("n/a", "n/a");
    }
    let (issuer, ticker, _) = res.unwrap();
    info!(
        "Validating asset issuance{{tx_id: {}, issuer: {}, ticker: {}}}",
        tx_id, issuer, ticker,
    );

    let issuer_ordered_pub_account: Result<OrderedPubAccount, Error> = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &issuer,
        &user_public_account_file(&ticker),
    );
    if let Err(error) = issuer_ordered_pub_account {
        error!("Error in validation of tx-{}: {:#?}", tx_id, error);
        return ValidationResult::error(&issuer, &ticker);
    }
    let issuer_ordered_pub_account = issuer_ordered_pub_account.unwrap();

    let issuer_account_balance: Result<EncryptedAmount, Error> = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &issuer,
        &user_public_account_balance_file(&ticker),
    );
    if let Err(error) = issuer_account_balance {
        error!("Error in validation of tx-{}: {:#?}", tx_id, error);
        return ValidationResult::error(&issuer, &ticker);
    }
    let issuer_account_balance = issuer_account_balance.unwrap();

    timing!(
        "validator.issuance.load_objects",
        load_objects_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    let validate_issuance_transaction_timer = Instant::now();

    let validator = AssetValidator;
    // TODO: CRYP-165: This requires more work to handle properly. At the moment, I am ignoring the the balance returned.
    let _ = match validator
        .verify_asset_transaction(
            amount,
            &asset_tx,
            &issuer_ordered_pub_account.pub_account,
            &issuer_account_balance,
            &[],
        )
        .map_err(|error| Error::LibraryError { error })
    {
        Err(error) => {
            error!("Error in validation of tx-{}: {:#?}", tx_id, error);
            return ValidationResult::error(&issuer, &ticker);
        }
        Ok(pub_account) => pub_account,
    };

    timing!(
        "validator.issuance.transaction",
        validate_issuance_transaction_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    let save_objects_timer = Instant::now();
    // Save the transaction under the new state.
    let new_state = AssetTxState::Justification(TxSubstate::Validated);
    let instruction = AssetInstruction {
        state: new_state,
        data: asset_tx.encode().to_vec(),
    };
    if let Err(error) = save_object(
        db_dir,
        ON_CHAIN_DIR,
        &issuer,
        &asset_transaction_file(tx_id, &issuer, new_state),
        &instruction,
    ) {
        error!("Error in validation of tx-{}: {:#?}", tx_id, error);
        return ValidationResult::error(&issuer, &ticker);
    }

    timing!(
        "validator.issuance.save_objects",
        save_objects_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    ValidationResult {
        user: issuer,
        ticker,
        amount: Some(asset_tx.memo.enc_issued_amount),
        direction: Direction::Incoming,
    }
}

pub fn validate_account(db_dir: PathBuf, asset_id: AssetId) -> Result<(), Error> {
    // Load the user's public account.
    let (user, ticker, tx_id) = get_user_ticker_from(asset_id, db_dir.clone())?;
    info!(
        "Validating account{{tx_id: {}, asset_id: {}, user: {}, ticker: {}}}",
        tx_id,
        PrintableAccountId(asset_id.encode()),
        user,
        ticker
    );
    let ordered_user_account_tx: OrderedPubAccountTx = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        COMMON_OBJECTS_DIR,
        &account_create_transaction_file(tx_id, &user, &ticker),
    )?;

    // Validate the account.
    let validate_account_timer = Instant::now();
    let account_validator = AccountValidator {};
    account_validator
        .verify(&ordered_user_account_tx.account_tx)
        .map_err(|error| Error::LibraryError { error })?;

    timing!(
        "validator.account",
        validate_account_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    // On success save the public account as validated.
    let save_objects_timer = Instant::now();
    let ordered_account = OrderedPubAccount {
        pub_account: ordered_user_account_tx.account_tx.pub_account,
        last_processed_tx_counter: Some(tx_id),
    };
    save_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &user,
        &user_public_account_file(&ticker),
        &ordered_account,
    )?;
    save_object(
        db_dir,
        ON_CHAIN_DIR,
        &user,
        &user_public_account_balance_file(&ticker),
        &ordered_user_account_tx.account_tx.initial_balance,
    )?;

    timing!(
        "validator.account.save_objects",
        save_objects_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    Ok(())
}

fn process_transaction(
    instruction: TransferInstruction,
    sender_pub_account: PubAccount,
    receiver_pub_account: PubAccount,
    pending_balance: EncryptedAmount,
) -> Result<(), Error> {
    let mut rng = OsRng::default();
    let (init_tx, finalized_tx) =
        <(InitializedTransferTx, FinalizedTransferTx)>::decode(&mut &instruction.data[..]).unwrap();
    let validator = TransactionValidator;
    validator
        .verify_transaction(
            &init_tx,
            &finalized_tx,
            &sender_pub_account,
            &pending_balance,
            &receiver_pub_account,
            &[],
            &mut rng,
        )
        .map_err(|error| Error::LibraryError { error })
}

pub fn validate_transaction(
    db_dir: PathBuf,
    init_tx: InitializedTransferTx,
    _finalized_tx: FinalizedTransferTx,
    mediator: String,
    pending_balance: EncryptedAmount,
    tx_id: u32,
) -> (ValidationResult, ValidationResult) {
    let load_objects_timer = Instant::now();
    // Load the transaction, mediator's account, and issuer's public account.

    let (sender, _, _) =
        match get_user_ticker_from(init_tx.memo.sender_account.asset_id, db_dir.clone()) {
            Err(error) => {
                error!("Error in validation of tx-{}: {:#?}", tx_id, error);
                return (
                    ValidationResult::error("n/a", "n/a"),
                    ValidationResult::error("n/a", "n/a"),
                );
            }
            Ok(ok) => ok,
        };

    let (receiver, ticker, _) =
        match get_user_ticker_from(init_tx.memo.receiver_account.asset_id, db_dir.clone()) {
            Err(error) => {
                error!("Error in validation of tx-{}: {:#?}", tx_id, error);
                return (
                    ValidationResult::error("n/a", "n/a"),
                    ValidationResult::error("n/a", "n/a"),
                );
            }
            Ok(ok) => ok,
        };

    info!(
        "Validating asset transfer{{tx_id: {}, sender: {}, receiver: {}, ticker:{}, mediator: {}}}",
        tx_id, sender, receiver, ticker, mediator
    );
    let state = TransferTxState::Justification(TxSubstate::Started);

    let mut instruction: TransferInstruction = match load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        COMMON_OBJECTS_DIR,
        &confidential_transaction_file(tx_id, &mediator, state),
    ) {
        Err(error) => {
            error!("Error in validation of tx-{}: {:#?}", tx_id, error);
            return (
                ValidationResult::error(&sender, &ticker),
                ValidationResult::error(&receiver, &ticker),
            );
        }
        Ok(ok) => ok,
    };

    let sender_ordered_pub_account: OrderedPubAccount = match load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &sender,
        &user_public_account_file(&ticker),
    ) {
        Err(error) => {
            error!("Error in validation of tx-{}: {:#?}", tx_id, error);
            return (
                ValidationResult::error(&sender, &ticker),
                ValidationResult::error(&receiver, &ticker),
            );
        }
        Ok(ok) => ok,
    };

    let receiver_ordered_pub_account: OrderedPubAccount = match load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &receiver,
        &user_public_account_file(&ticker),
    ) {
        Err(error) => {
            error!("Error in validation of tx-{}: {:#?}", tx_id, error);
            return (
                ValidationResult::error(&sender, &ticker),
                ValidationResult::error(&receiver, &ticker),
            );
        }
        Ok(ok) => ok,
    };

    timing!(
        "validator.issuance.load_objects",
        load_objects_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    let validate_transaction_timer = Instant::now();
    let _result = match process_transaction(
        instruction.clone(),
        sender_ordered_pub_account.pub_account,
        receiver_ordered_pub_account.pub_account,
        pending_balance,
    ) {
        Err(error) => {
            error!("Error in validation of tx-{}: {:#?}", tx_id, error);
            return (
                ValidationResult::error(&sender, &ticker),
                ValidationResult::error(&receiver, &ticker),
            );
        }
        Ok(ok) => ok,
    };

    timing!(
        "validator.transaction",
        validate_transaction_timer,
        Instant::now(),
        "tx_id" =>  tx_id.to_string()
    );

    let save_objects_timer = Instant::now();
    // Save the transaction under the new state.
    instruction.state = TransferTxState::Justification(TxSubstate::Validated);
    if let Err(error) = save_object(
        db_dir,
        ON_CHAIN_DIR,
        COMMON_OBJECTS_DIR,
        &confidential_transaction_file(tx_id, &sender, instruction.state),
        &instruction,
    ) {
        error!("Error in validation of tx-{}: {:#?}", tx_id, error);
        return (
            ValidationResult::error(&sender, &ticker),
            ValidationResult::error(&receiver, &ticker),
        );
    }

    timing!(
        "validator.issuance.save_objects",
        save_objects_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    (
        ValidationResult {
            user: sender,
            ticker: ticker.clone(),
            direction: Direction::Outgoing,
            amount: Some(init_tx.memo.enc_amount_using_sender),
        },
        ValidationResult {
            user: receiver,
            ticker,
            direction: Direction::Incoming,
            amount: Some(init_tx.memo.enc_amount_using_receiver),
        },
    )
}
