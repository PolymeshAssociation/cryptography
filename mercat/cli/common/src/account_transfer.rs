use crate::{
    compute_enc_pending_balance, confidential_transaction_file, construct_path,
    create_rng_from_seed, debug_decrypt, errors::Error, last_ordering_state, load_object,
    save_object, user_public_account_balance_file, user_public_account_file,
    user_secret_account_file, OrderedPubAccount, OrderedTransferInstruction, OrderingState,
    COMMON_OBJECTS_DIR, MEDIATOR_PUBLIC_ACCOUNT_FILE, OFF_CHAIN_DIR, ON_CHAIN_DIR,
};
use codec::{Decode, Encode};
use confidential_identity_core::asset_proofs::Balance;
use log::{debug, info};
use mercat::{
    transaction::{CtxReceiver, CtxSender},
    Account, EncryptedAmount, EncryptionPubKey, InitializedTransferTx, PubAccount,
    TransferTransactionReceiver, TransferTransactionSender, TransferTxState, TxSubstate,
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
    amount: Balance,
    stdout: bool,
    tx_id: u32,
    cheat: bool,
) -> Result<(), Error> {
    let mut rng = create_rng_from_seed(Some(seed))?;
    let load_from_file_timer = Instant::now();

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
    let sender_account = Account {
        secret: load_object(
            db_dir.clone(),
            OFF_CHAIN_DIR,
            &sender,
            &user_secret_account_file(&ticker),
        )?,
        public: sender_ordered_pub_account.pub_account,
    };

    let receiver_account: OrderedPubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &receiver,
        &user_public_account_file(&ticker),
    )?;

    let mediator_account: EncryptionPubKey = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &mediator,
        MEDIATOR_PUBLIC_ACCOUNT_FILE,
    )?;

    timing!(
        "account.create_tx.load_from_file",
        load_from_file_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    // Calculate the pending
    let calc_pending_state_timer = Instant::now();
    let last_processed_tx_counter = sender_ordered_pub_account.last_processed_tx_counter;
    let last_processed_account_balance = sender_account_balance;
    let ordering_state = last_ordering_state(
        sender.clone(),
        last_processed_tx_counter,
        tx_id,
        db_dir.clone(),
    )?;

    let pending_enc_balance = compute_enc_pending_balance(
        &sender,
        ordering_state.clone(),
        last_processed_tx_counter,
        last_processed_account_balance,
        db_dir.clone(),
    )?;
    let pending_balance =
        debug_decrypt(&sender_account.public, pending_enc_balance, db_dir.clone())?;
    debug!(
        "------------> initiating transfer tx: {}, pending_balance: {}",
        tx_id, pending_balance
    );
    let next_pending_tx_counter = ordering_state.last_pending_tx_counter + 1;

    timing!(
        "account.create_tx.calc_pending_state",
        calc_pending_state_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    let mut amount = amount;

    // The first cheating strategies make changes to the input, while the subsequent ones
    // changes the output.
    if cheat {
        info!(
            "CLI log: tx-{}: Cheating by changing the agreed upon amount. Correct amount: {}",
            tx_id, amount
        );
        amount += 1
    }

    // Initialize the transaction.
    let create_tx_timer = Instant::now();
    let ctx_sender = CtxSender {};
    let pending_account = Account {
        secret: sender_account.secret,
        public: PubAccount {
            owner_enc_pub_key: sender_account.public.owner_enc_pub_key,
        },
    };
    let init_tx = ctx_sender
        .create_transaction(
            &pending_account,
            &pending_enc_balance,
            pending_balance,
            &receiver_account.pub_account,
            &mediator_account,
            &[],
            amount,
            &mut rng,
        )
        .map_err(|error| Error::LibraryError { error })?;

    let ordering_state = OrderingState {
        last_processed_tx_counter: sender_ordered_pub_account.last_processed_tx_counter,
        last_pending_tx_counter: next_pending_tx_counter,
        tx_id,
    };
    timing!("account.create_tx.create", create_tx_timer, Instant::now());

    // Save the artifacts to file.
    let new_state = TransferTxState::Initialization(TxSubstate::Started);
    let save_to_file_timer = Instant::now();
    let instruction = OrderedTransferInstruction {
        state: new_state,
        ordering_state,
        data: init_tx.encode().to_vec(),
    };

    save_object(
        db_dir,
        ON_CHAIN_DIR,
        COMMON_OBJECTS_DIR,
        &confidential_transaction_file(tx_id, &sender, new_state),
        &instruction,
    )?;

    if stdout {
        info!(
            "CLI log: tx-{}: Transaction as base64:\n{}\n",
            tx_id,
            base64::encode(init_tx.encode())
        );
    }

    timing!(
        "account.create_tx.save_to_file",
        save_to_file_timer,
        Instant::now()
    );

    Ok(())
}

pub fn process_finalize_tx(
    db_dir: PathBuf,
    sender: String,
    receiver: String,
    ticker: String,
    amount: Balance,
    stdout: bool,
    tx_id: u32,
    cheat: bool,
) -> Result<(), Error> {
    let load_from_file_timer = Instant::now();
    let state = TransferTxState::Initialization(TxSubstate::Started);

    let receiver_ordered_pub_account: OrderedPubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &receiver,
        &user_public_account_file(&ticker),
    )?;
    let receiver_account = Account {
        secret: load_object(
            db_dir.clone(),
            OFF_CHAIN_DIR,
            &receiver,
            &user_secret_account_file(&ticker),
        )?,
        public: receiver_ordered_pub_account.pub_account,
    };

    let instruction: OrderedTransferInstruction = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        COMMON_OBJECTS_DIR,
        &confidential_transaction_file(tx_id, &sender, state),
    )?;

    let init_tx = InitializedTransferTx::decode(&mut &instruction.data[..]).map_err(|error| {
        Error::ObjectLoadError {
            error,
            path: construct_path(
                db_dir.clone(),
                ON_CHAIN_DIR,
                &sender.clone(),
                &confidential_transaction_file(tx_id, &sender, state),
            ),
        }
    })?;

    timing!(
        "account.finalize_tx.load_from_file",
        load_from_file_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    // Calculate the pending
    let calc_pending_state_timer = Instant::now();
    let ordering_state = last_ordering_state(
        receiver,
        receiver_ordered_pub_account.last_processed_tx_counter,
        tx_id,
        db_dir.clone(),
    )?;
    let next_pending_tx_counter = ordering_state.last_pending_tx_counter + 1;

    timing!(
        "account.finalize_tx.calc_pending_state",
        calc_pending_state_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    let mut amount = amount;

    // The first cheating strategies make changes to the input, while the 2nd one
    // changes the output.
    if cheat {
        info!(
            "CLI log: tx-{}: Cheating by changing the agreed upon amount. Correct amount: {}",
            tx_id, amount
        );
        amount += 1
    }

    // Finalize the transaction.
    let finalize_by_receiver_timer = Instant::now();
    let receiver = CtxReceiver {};
    let finalized_tx = receiver
        .finalize_transaction(&init_tx, receiver_account.clone(), amount)
        .map_err(|error| Error::LibraryError { error })?;

    let ordering_state = OrderingState {
        last_processed_tx_counter: receiver_ordered_pub_account.last_processed_tx_counter,
        last_pending_tx_counter: next_pending_tx_counter,
        tx_id,
    };

    timing!(
        "account.finalize_tx.finalize_by_receiver",
        finalize_by_receiver_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    // Save the artifacts to file.
    let save_to_file_timer = Instant::now();
    let state = TransferTxState::Finalization(TxSubstate::Started);
    let instruction = OrderedTransferInstruction {
        state,
        ordering_state,
        data: (&init_tx, &finalized_tx).encode().to_vec(),
    };

    save_object(
        db_dir,
        ON_CHAIN_DIR,
        COMMON_OBJECTS_DIR,
        &confidential_transaction_file(tx_id, &sender, state),
        &instruction,
    )?;

    if stdout {
        info!(
            "CLI log: tx-{}: Transaction as base64:\n{}\n",
            tx_id,
            base64::encode(finalized_tx.encode())
        );
    }

    timing!(
        "account.finalize_tx.save_to_file",
        save_to_file_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    Ok(())
}
