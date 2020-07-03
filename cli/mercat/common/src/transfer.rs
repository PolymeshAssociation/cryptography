use crate::{
    confidential_transaction_file, construct_path, create_rng_from_seed, errors::Error,
    load_object, save_object, CTXInstruction, Instruction, OFF_CHAIN_DIR, ON_CHAIN_DIR,
    PUBLIC_ACCOUNT_FILE, SECRET_ACCOUNT_FILE, VALIDATED_PUBLIC_ACCOUNT_FILE,
};
use codec::{Decode, Encode};
use cryptography::mercat::{
    conf_tx::CtxReceiver, conf_tx::CtxSender, Account, AccountMemo, ConfidentialTransactionSender,
    ConfidentialTxState, PubAccount, PubInitConfidentialTxData, TxSubstate,
};
use metrics::timing;
use std::{path::PathBuf, time::Instant};

pub fn process_create_tx(
    seed: String,
    db_dir: PathBuf,
    sender: String,
    receiver: String,
    mediator: String,
    ticker: String,
    amount: u32,
    tx_id: u32,
) -> Result<(), Error> {
    let mut rng = create_rng_from_seed(Some(seed))?;
    let load_from_file_timer = Instant::now();

    let sender_account = Account {
        scrt: load_object(
            db_dir.clone(),
            OFF_CHAIN_DIR,
            &sender,
            &format!("{}_{}", ticker, SECRET_ACCOUNT_FILE),
        )?,
        pblc: load_object(
            db_dir.clone(),
            ON_CHAIN_DIR,
            &sender,
            &format!("{}_{}", ticker, VALIDATED_PUBLIC_ACCOUNT_FILE),
        )?,
    };

    let receiver_account: PubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &receiver,
        &format!("{}_{}", ticker, PUBLIC_ACCOUNT_FILE),
    )?;

    let mediator_account: AccountMemo =
        load_object(db_dir.clone(), ON_CHAIN_DIR, &mediator, PUBLIC_ACCOUNT_FILE)?;

    timing!(
        "account.create_tx.load_from_file",
        load_from_file_timer,
        Instant::now()
    );

    // Initialize the transaction.
    let create_tx_timer = Instant::now();
    let ctx_sender = CtxSender {};
    let (asset_tx, state) = ctx_sender
        .create_transaction(
            &sender_account,
            &receiver_account,
            &mediator_account.owner_enc_pub_key,
            amount,
            &mut rng,
        )
        .map_err(|error| Error::LibraryError { error })?;
    timing!("account.create_tx.create", create_tx_timer, Instant::now());

    // Save the artifacts to file.
    let save_to_file_timer = Instant::now();
    let instruction = CTXInstruction {
        state,
        data: asset_tx.encode().to_vec(),
    };

    // TODO(CRYP-110)
    // We should name the transactions based on the ordering counters, or we may decide that
    // a global counter (tx_id) is enough and put all transactions inside a common folder.
    save_object(
        db_dir,
        ON_CHAIN_DIR,
        &sender,
        &confidential_transaction_file(tx_id, state),
        &instruction,
    )?;

    timing!(
        "account.create_tx.save_to_file",
        save_to_file_timer,
        Instant::now()
    );

    Ok(())
}

pub fn process_finalize_tx(
    seed: String,
    db_dir: PathBuf,
    sender: String,
    receiver: String,
    ticker: String,
    amount: u32,
    tx_id: u32,
) -> Result<(), Error> {
    let mut rng = create_rng_from_seed(Some(seed))?;
    let load_from_file_timer = Instant::now();

    let receiver_account = Account {
        scrt: load_object(
            db_dir.clone(),
            OFF_CHAIN_DIR,
            &receiver,
            &format!("{}_{}", ticker, SECRET_ACCOUNT_FILE),
        )?,
        pblc: load_object(
            db_dir.clone(),
            ON_CHAIN_DIR,
            &receiver,
            &format!("{}_{}", ticker, PUBLIC_ACCOUNT_FILE),
        )?,
    };

    let instruction: Instruction = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &sender,
        &confidential_transaction_file(
            tx_id.clone(),
            ConfidentialTxState::Initialization(TxSubstate::Validated),
        ),
    )?;

    let tx = PubInitConfidentialTxData::decode(&mut &instruction.data[..]).map_err(|error| {
        Error::ObjectLoadError {
            error,
            path: construct_path(
                db_dir.clone(),
                ON_CHAIN_DIR,
                &sender.clone(),
                PUBLIC_ACCOUNT_FILE,
            ),
        }
    })?;

    timing!(
        "account.finalize_tx.load_from_file",
        load_from_file_timer,
        Instant::now()
    );

    // Finalize the transaction.
    let finalize_by_receiver_timer = Instant::now();
    let receiver = CtxReceiver {};
    let (asset_tx, state) = receiver
        .finalize_by_receiver(
            tx,
            receiver_account,
            ConfidentialTxState::Initialization(TxSubstate::Validated),
            amount,
            &mut rng,
        )
        .map_err(|error| Error::LibraryError { error })?;

    timing!(
        "account.finalize_tx.finalize_by_receiver",
        finalize_by_receiver_timer,
        Instant::now()
    );

    // Save the artifacts to file.
    let save_to_file_timer = Instant::now();
    let instruction = CTXInstruction {
        state,
        data: asset_tx.encode().to_vec(),
    };

    // TODO(CRYP-110)
    // We should name the transactions based on the ordering counters, or we may decide that
    // a global counter (tx_id) is enough and put all transactions inside a common folder.
    save_object(
        db_dir,
        ON_CHAIN_DIR,
        &sender,
        &confidential_transaction_file(tx_id, state),
        &instruction,
    )?;

    timing!(
        "account.finalize_tx.save_to_file",
        save_to_file_timer,
        Instant::now()
    );

    Ok(())
}
