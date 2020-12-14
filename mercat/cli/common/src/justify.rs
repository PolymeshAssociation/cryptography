use crate::{
    compute_enc_pending_balance, confidential_transaction_file, construct_path,
    create_rng_from_seed, errors::Error, last_ordering_state, load_object, non_empty_account_id,
    save_object, user_public_account_balance_file, user_public_account_file, OrderedPubAccount,
    OrderedTransferInstruction, TransferInstruction, COMMON_OBJECTS_DIR,
    MEDIATOR_PUBLIC_ACCOUNT_FILE, OFF_CHAIN_DIR, ON_CHAIN_DIR, SECRET_ACCOUNT_FILE,
};
use codec::{Decode, Encode};
use cryptography_core::{asset_id_from_ticker, asset_proofs::ElgamalSecretKey};
use curve25519_dalek::scalar::Scalar;
use log::info;
use mercat::{
    transaction::CtxMediator, EncryptedAmount, EncryptionKeys, EncryptionPubKey,
    FinalizedTransferTx, MediatorAccount, TransferTransactionMediator, TransferTxState, TxSubstate,
};
use metrics::timing;
use rand::{CryptoRng, RngCore};
use std::{path::PathBuf, time::Instant};

fn generate_mediator_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (EncryptionPubKey, MediatorAccount) {
    let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(rng));
    let mediator_enc_key = EncryptionKeys {
        public: mediator_elg_secret_key.get_public_key(),
        secret: mediator_elg_secret_key,
    };

    (
        mediator_enc_key.public,
        MediatorAccount {
            encryption_key: mediator_enc_key,
        },
    )
}

pub fn process_create_mediator(seed: String, db_dir: PathBuf, user: String) -> Result<(), Error> {
    // Setup the rng.
    let mut rng = create_rng_from_seed(Some(seed))?;

    // Generate keys for the mediator.
    let mediator_key_gen_timer = Instant::now();
    let (public_account, private_account) = generate_mediator_keys(&mut rng);
    timing!(
        "mediator.key_gen",
        mediator_key_gen_timer,
        Instant::now(),
        "tx_id" => "N/A"
    );

    let mediator_save_keys_timer = Instant::now();
    save_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &user,
        MEDIATOR_PUBLIC_ACCOUNT_FILE,
        &public_account,
    )?;

    save_object(
        db_dir,
        OFF_CHAIN_DIR,
        &user,
        SECRET_ACCOUNT_FILE,
        &private_account,
    )?;
    info!(
        "CLI log: Mediator keys as base64:\n{}\n",
        base64::encode(public_account.encode())
    );
    timing!(
        "mediator.save_keys",
        mediator_save_keys_timer,
        Instant::now(),
        "tx_id" => "N/A"
    );

    Ok(())
}

pub fn justify_asset_transfer_transaction(
    db_dir: PathBuf,
    sender: String,
    receiver: String,
    mediator: String,
    ticker: String,
    seed: String,
    stdout: bool,
    tx_id: u32,
    reject: bool,
    cheat: bool,
) -> Result<(), Error> {
    // Load the transaction, mediator's credentials, and issuer's public account.
    let justify_load_objects_timer = Instant::now();
    let mut rng = create_rng_from_seed(Some(seed))?;

    let instruction_path = confidential_transaction_file(
        tx_id,
        &sender,
        TransferTxState::Finalization(TxSubstate::Started),
    );
    let instruction: OrderedTransferInstruction = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        COMMON_OBJECTS_DIR,
        &instruction_path,
    )?;

    let asset_tx = FinalizedTransferTx::decode(&mut &instruction.data[..]).map_err(|error| {
        Error::ObjectLoadError {
            error,
            path: construct_path(
                db_dir.clone(),
                ON_CHAIN_DIR,
                COMMON_OBJECTS_DIR,
                &instruction_path,
            ),
        }
    })?;

    let mediator_account: MediatorAccount = load_object(
        db_dir.clone(),
        OFF_CHAIN_DIR,
        &mediator,
        SECRET_ACCOUNT_FILE,
    )?;

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

    let receiver_ordered_pub_account: OrderedPubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &receiver,
        &user_public_account_file(&ticker),
    )?;

    timing!(
        "mediator.justify_tx.load_objects",
        justify_load_objects_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    // Justification.
    let justify_library_timer = Instant::now();

    // Calculate the pending
    let last_processed_tx_counter = sender_ordered_pub_account.last_processed_tx_counter;
    let last_processed_account_balance = sender_account_balance;
    let ordering_state = last_ordering_state(
        sender.clone(),
        last_processed_tx_counter,
        tx_id,
        db_dir.clone(),
    )?;

    let pending_balance = compute_enc_pending_balance(
        &sender,
        ordering_state,
        last_processed_tx_counter,
        last_processed_account_balance,
        db_dir.clone(),
    )?;

    let asset_id = asset_id_from_ticker(&ticker).map_err(|error| Error::LibraryError { error })?;
    let mut justified_tx = CtxMediator
        .justify_transaction(
            asset_tx.clone(),
            &mediator_account.encryption_key,
            &sender_ordered_pub_account.pub_account,
            &pending_balance,
            &receiver_ordered_pub_account.pub_account,
            &[],
            asset_id,
            &mut rng,
        )
        .map_err(|error| Error::LibraryError { error })?;

    if cheat {
        info!(
            "CLI log: tx-{}: Cheating by overwriting the sender's account id.",
            tx_id
        );

        justified_tx.finalized_data.init_data.memo.sender_account_id += non_empty_account_id();
    }

    timing!(
        "mediator.justify_tx.library",
        justify_library_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    let next_instruction;
    let justify_save_objects_timer = Instant::now();
    // If the `reject` flag is set, save the transaction as rejected.
    if reject {
        let rejected_state = TransferTxState::Justification(TxSubstate::Rejected);
        next_instruction = TransferInstruction {
            data: asset_tx.encode().to_vec(),
            state: rejected_state,
        };

        save_object(
            db_dir,
            ON_CHAIN_DIR,
            COMMON_OBJECTS_DIR,
            &confidential_transaction_file(tx_id, &sender, rejected_state),
            &next_instruction,
        )?;
        if stdout {
            info!(
                "CLI log: tx-{}: Transaction as base64:\n{}\n",
                tx_id,
                base64::encode(asset_tx.encode())
            );
        }
    } else {
        let new_state = TransferTxState::Justification(TxSubstate::Started);
        // Save the updated_issuer_account, and the justified transaction.
        next_instruction = TransferInstruction {
            data: justified_tx.encode().to_vec(),
            state: new_state,
        };

        save_object(
            db_dir,
            ON_CHAIN_DIR,
            COMMON_OBJECTS_DIR,
            &confidential_transaction_file(tx_id, &mediator, new_state),
            &next_instruction,
        )?;
        if stdout {
            info!(
                "CLI log: tx-{}: Transaction as base64:\n{}\n",
                tx_id,
                base64::encode(justified_tx.encode())
            );
        }
    }

    timing!(
        "mediator.justify_tx.save_objects",
        justify_save_objects_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    Ok(())
}
