use crate::{
    asset_transaction_file, confidential_transaction_file, errors::Error, get_asset_ids,
    load_object, save_object, CTXInstruction, Instruction, FINISHED_STATE, INIT_STATE,
    JUSTIFICATION_STATE, JUSTIFY_STATE, ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE,
    VALIDATED_PUBLIC_ACCOUNT_FILE,
};
use codec::Decode;
use cryptography::mercat::{
    account::AccountValidator,
    asset::AssetTxIssueValidator,
    conf_tx::{CtxMediatorValidator, CtxReceiverValidator, CtxSenderValidator},
    AccountCreatorVerifier, AccountMemo, AssetTransactionFinalizeAndProcessVerifier,
    AssetTransactionInitializeVerifier, AssetTxState, ConfidentialTransactionFinalizationVerifier,
    ConfidentialTransactionInitVerifier, ConfidentialTransactionMediatorVerifier,
    ConfidentialTxState, JustifiedPubFinalConfidentialTxData, PubAccount, PubAssetTxData,
    PubFinalConfidentialTxData, PubInitConfidentialTxData, PubJustifiedAssetTxData, TxSubstate,
};
use metrics::timing;
use std::{path::PathBuf, time::Instant};

fn process_asset_issuance_init(
    instruction: Instruction,
    mdtr_account: &AccountMemo,
    issr_pub_account: &PubAccount,
) -> Result<AssetTxState, Error> {
    let tx = PubAssetTxData::decode(&mut &instruction.data[..]).unwrap();
    let validator = AssetTxIssueValidator {};
    let state = validator
        .verify_initialization(
            &tx,
            instruction.state,
            &issr_pub_account,
            &mdtr_account.owner_enc_pub_key,
        )
        .map_err(|error| Error::LibraryError { error })?;

    Ok(state)
}

fn process_asset_issuance_justification(
    instruction: Instruction,
    mdtr_account: &AccountMemo,
    issr_pub_account: &PubAccount,
) -> Result<AssetTxState, Error> {
    let tx = PubJustifiedAssetTxData::decode(&mut &instruction.data[..]).unwrap();
    let validator = AssetTxIssueValidator {};
    let state = validator
        .verify_justification(&tx, issr_pub_account, &mdtr_account.owner_sign_pub_key)
        .map_err(|error| Error::LibraryError { error })?;

    Ok(state)
}

pub fn validate_asset_issuance(
    db_dir: PathBuf,
    issuer: String,
    mediator: String,
    state: String,
    tx_id: u32,
    ticker: String,
) -> Result<(), Error> {
    let load_objects_timer = Instant::now();

    let state = match state.as_str() {
        INIT_STATE => AssetTxState::Initialization(TxSubstate::Started),
        JUSTIFY_STATE => AssetTxState::Justification(TxSubstate::Started),
        _ => return Err(Error::InvalidInstructionError),
    };

    let mut instruction: Instruction = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &issuer,
        &asset_transaction_file(tx_id, state),
    )?;

    let mediator_account: AccountMemo =
        load_object(db_dir.clone(), ON_CHAIN_DIR, &mediator, PUBLIC_ACCOUNT_FILE)?;

    let issuer_account: PubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &issuer,
        &format!("{}_{}", ticker, VALIDATED_PUBLIC_ACCOUNT_FILE),
    )?;
    timing!(
        "validator.issuance.load_objects",
        load_objects_timer,
        Instant::now()
    );

    let validate_issuance_transaction_timer = Instant::now();
    let result = match instruction.state {
        AssetTxState::Initialization(TxSubstate::Started) => {
            process_asset_issuance_init(instruction.clone(), &mediator_account, &issuer_account)?
        }
        AssetTxState::Justification(TxSubstate::Started) => process_asset_issuance_justification(
            instruction.clone(),
            &mediator_account,
            &issuer_account,
        )?,
        _ => return Err(Error::InvalidInstructionError),
    };

    timing!(
        "validator.issuance.transaction",
        validate_issuance_transaction_timer,
        Instant::now()
    );

    let save_objects_timer = Instant::now();
    // Save the transaction under the new state.
    instruction.state = result;
    save_object(
        db_dir,
        ON_CHAIN_DIR,
        &issuer,
        &asset_transaction_file(tx_id, result),
        &instruction,
    )?;
    timing!(
        "validator.issuance.save_objects",
        save_objects_timer,
        Instant::now()
    );

    Ok(())
}

pub fn validate_account(db_dir: PathBuf, user: String, ticker: String) -> Result<(), Error> {
    // Load the user's public account.
    let load_objects_timer = Instant::now();

    let user_account: PubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &user,
        &format!("{}_{}", ticker, PUBLIC_ACCOUNT_FILE),
    )?;

    let valid_asset_ids = get_asset_ids(db_dir.clone())?;
    timing!(
        "validator.account.load_objects",
        load_objects_timer,
        Instant::now()
    );

    // Validate the account.
    let validate_account_timer = Instant::now();
    let account_validator = AccountValidator {};
    account_validator
        .verify(&user_account, &valid_asset_ids)
        .map_err(|error| Error::LibraryError { error })?;

    timing!("validator.account", validate_account_timer, Instant::now());

    // On success save the public account as validated.
    let save_objects_timer = Instant::now();
    save_object(
        db_dir,
        ON_CHAIN_DIR,
        &user,
        &format!("{}_{}", ticker, VALIDATED_PUBLIC_ACCOUNT_FILE),
        &user_account,
    )?;
    timing!(
        "validator.account.save_objects",
        save_objects_timer,
        Instant::now()
    );

    Ok(())
}

fn process_transaction_initialization(
    instruction: CTXInstruction,
    sender_pub_account: &PubAccount,
) -> Result<ConfidentialTxState, Error> {
    let tx = PubInitConfidentialTxData::decode(&mut &instruction.data[..]).unwrap();
    let validator = CtxSenderValidator {};
    let state = validator
        .verify(&tx, sender_pub_account, instruction.state)
        .map_err(|error| Error::LibraryError { error })?;

    Ok(state)
}

fn process_transaction_finalization(
    instruction: CTXInstruction,
    sender_pub_account: &PubAccount,
    receiver_pub_account: &PubAccount,
) -> Result<ConfidentialTxState, Error> {
    let tx = PubFinalConfidentialTxData::decode(&mut &instruction.data[..]).unwrap();
    let validator = CtxReceiverValidator {};
    let state = validator
        .verify_finalize_by_receiver(
            sender_pub_account,
            receiver_pub_account,
            &tx,
            instruction.state,
        )
        .map_err(|error| Error::LibraryError { error })?;

    Ok(state)
}

fn process_transaction_finalization_justification(
    instruction: CTXInstruction,
    mdtr_account: &AccountMemo,
) -> Result<ConfidentialTxState, Error> {
    let tx = JustifiedPubFinalConfidentialTxData::decode(&mut &instruction.data[..]).unwrap();
    let validator = CtxMediatorValidator {};
    let state = validator
        .verify(&tx, &mdtr_account.owner_sign_pub_key, instruction.state)
        .map_err(|error| Error::LibraryError { error })?;

    Ok(state)
}

pub fn validate_transaction(
    db_dir: PathBuf,
    sender: String,
    receiver: String,
    mediator: String,
    state: String,
    tx_id: u32,
    ticker: String,
) -> Result<(), Error> {
    let load_objects_timer = Instant::now();
    // Load the transaction, mediator's account, and issuer's public account.

    let state = match state.as_str() {
        INIT_STATE => ConfidentialTxState::Initialization(TxSubstate::Started),
        FINISHED_STATE => ConfidentialTxState::Finalization(TxSubstate::Started),
        JUSTIFICATION_STATE => ConfidentialTxState::FinalizationJustification(TxSubstate::Started),
        _ => return Err(Error::InvalidInstructionError),
    };

    let mut instruction: CTXInstruction = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &sender,
        &confidential_transaction_file(tx_id, state),
    )?;

    let mediator_account: AccountMemo =
        load_object(db_dir.clone(), ON_CHAIN_DIR, &mediator, PUBLIC_ACCOUNT_FILE)?;

    let sender_account: PubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &sender,
        &format!("{}_{}", ticker, VALIDATED_PUBLIC_ACCOUNT_FILE),
    )?;

    let receiver_account: PubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &receiver,
        &format!("{}_{}", ticker, VALIDATED_PUBLIC_ACCOUNT_FILE),
    )?;

    timing!(
        "validator.issuance.load_objects",
        load_objects_timer,
        Instant::now()
    );

    let validate_transaction_timer = Instant::now();
    let result = match instruction.state {
        ConfidentialTxState::Initialization(TxSubstate::Started) => {
            process_transaction_initialization(instruction.clone(), &sender_account)?
        }
        ConfidentialTxState::Finalization(TxSubstate::Started) => process_transaction_finalization(
            instruction.clone(),
            &sender_account,
            &receiver_account,
        )?,
        ConfidentialTxState::FinalizationJustification(TxSubstate::Started) => {
            process_transaction_finalization_justification(instruction.clone(), &mediator_account)?
        }
        _ => return Err(Error::InvalidInstructionError),
    };

    timing!(
        "validator.transaction",
        validate_transaction_timer,
        Instant::now()
    );

    let save_objects_timer = Instant::now();
    // Save the transaction under the new state.
    instruction.state = result;
    save_object(
        db_dir,
        ON_CHAIN_DIR,
        &sender,
        &confidential_transaction_file(tx_id, result),
        &instruction,
    )?;
    timing!(
        "validator.issuance.save_objects",
        save_objects_timer,
        Instant::now()
    );

    Ok(())
}
