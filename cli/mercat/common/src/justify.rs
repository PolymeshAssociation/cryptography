use crate::{
    asset_transaction_file, confidential_transaction_file, construct_path, create_rng_from_seed,
    errors::Error, load_object, save_object, CTXInstruction, Instruction, OFF_CHAIN_DIR,
    ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE, SECRET_ACCOUNT_FILE, VALIDATED_PUBLIC_ACCOUNT_FILE,
};
use codec::{Decode, Encode};
use cryptography::{
    asset_id_from_ticker,
    asset_proofs::ElgamalSecretKey,
    mercat::{
        asset::AssetMediator, transaction::CtxMediator, AccountMemo, AssetTransactionMediator,
        AssetTxState, EncryptionKeys, FinalizedTx, InitializedAssetTx, MediatorAccount, PubAccount,
        TransactionMediator, TxState, TxSubstate,
    },
};
use curve25519_dalek::scalar::Scalar;
use metrics::timing;
use rand::{CryptoRng, RngCore};
use schnorrkel::{ExpansionMode, MiniSecretKey};
use std::{path::PathBuf, time::Instant};

fn generate_mediator_keys<R: RngCore + CryptoRng>(rng: &mut R) -> (AccountMemo, MediatorAccount) {
    let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(rng));
    let mediator_enc_key = EncryptionKeys {
        pblc: mediator_elg_secret_key.get_public_key().into(),
        scrt: mediator_elg_secret_key.into(),
    };

    let mediator_signing_pair =
        MiniSecretKey::generate_with(rng).expand_to_keypair(ExpansionMode::Ed25519);

    (
        AccountMemo::new(mediator_enc_key.pblc, mediator_signing_pair.public),
        MediatorAccount {
            encryption_key: mediator_enc_key,
            signing_key: mediator_signing_pair,
        },
    )
}

pub fn process_create_mediator(seed: String, db_dir: PathBuf, user: String) -> Result<(), Error> {
    // Setup the rng.
    let mut rng = create_rng_from_seed(Some(seed))?;

    // Generate keys for the mediator.
    let mediator_key_gen_timer = Instant::now();
    let (public_account, private_account) = generate_mediator_keys(&mut rng);
    timing!("mediator.key_gen", mediator_key_gen_timer, Instant::now());

    let mediator_save_keys_timer = Instant::now();
    save_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &user,
        PUBLIC_ACCOUNT_FILE,
        &public_account,
    )?;

    save_object(
        db_dir,
        OFF_CHAIN_DIR,
        &user,
        SECRET_ACCOUNT_FILE,
        &private_account,
    )?;
    timing!(
        "mediator.save_keys",
        mediator_save_keys_timer,
        Instant::now()
    );

    Ok(())
}

pub fn justify_asset_issuance(
    db_dir: PathBuf,
    issuer: String,
    mediator: String,
    ticker: String,
    tx_id: u32,
    reject: bool,
) -> Result<(), Error> {
    // Load the transaction, mediator's credentials, and issuer's public account.
    let justify_load_objects_timer = Instant::now();

    let instruction_path =
        asset_transaction_file(tx_id, AssetTxState::Initialization(TxSubstate::Validated));

    let instruction: Instruction =
        load_object(db_dir.clone(), ON_CHAIN_DIR, &issuer, &instruction_path)?;

    let asset_tx = InitializedAssetTx::decode(&mut &instruction.data[..]).map_err(|error| {
        Error::ObjectLoadError {
            error,
            path: construct_path(db_dir.clone(), ON_CHAIN_DIR, &issuer, &instruction_path),
        }
    })?;

    let mediator_account: MediatorAccount = load_object(
        db_dir.clone(),
        OFF_CHAIN_DIR,
        &mediator,
        SECRET_ACCOUNT_FILE,
    )?;

    let issuer_account: PubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &issuer.clone(),
        &format!("{}_{}", ticker, VALIDATED_PUBLIC_ACCOUNT_FILE),
    )?;

    timing!(
        "mediator.justify_load_objects",
        justify_load_objects_timer,
        Instant::now()
    );

    // Justification.
    let justify_library_timer = Instant::now();
    let mediator = AssetMediator {};
    let justified_tx = mediator
        .justify_asset_transaction(
            asset_tx.clone(),
            &issuer_account,
            &mediator_account.encryption_key,
            &mediator_account.signing_key,
        )
        .map_err(|error| Error::LibraryError { error })?;
    timing!(
        "mediator.justify_library",
        justify_library_timer,
        Instant::now()
    );

    let next_instruction;
    let justify_save_objects_timer = Instant::now();
    // If the `reject` flag is set, save the transaction as rejected.
    if reject {
        let rejected_state = AssetTxState::Justification(TxSubstate::Rejected);
        next_instruction = Instruction {
            data: asset_tx.encode().to_vec(),
            state: rejected_state,
        };

        save_object(
            db_dir,
            ON_CHAIN_DIR,
            &issuer,
            &asset_transaction_file(tx_id, rejected_state),
            &next_instruction,
        )?;
    } else {
        // Save the updated_issuer_account, and the justified transaction.
        next_instruction = Instruction {
            data: justified_tx.encode().to_vec(),
            state: AssetTxState::Justification(TxSubstate::Started),
        };

        save_object(
            db_dir,
            ON_CHAIN_DIR,
            &issuer,
            &asset_transaction_file(tx_id, AssetTxState::Justification(TxSubstate::Started)),
            &next_instruction,
        )?;
    }

    timing!(
        "mediator.justify_save_objects",
        justify_save_objects_timer,
        Instant::now()
    );

    Ok(())
}

pub fn justify_asset_transaction(
    db_dir: PathBuf,
    sender: String,
    receiver: String,
    mediator: String,
    ticker: String,
    tx_id: u32,
    reject: bool,
) -> Result<(), Error> {
    // Load the transaction, mediator's credentials, and issuer's public account.
    let justify_load_objects_timer = Instant::now();

    let instruction_path =
        confidential_transaction_file(tx_id, TxState::Finalization(TxSubstate::Validated));
    let instruction: CTXInstruction =
        load_object(db_dir.clone(), ON_CHAIN_DIR, &sender, &instruction_path)?;

    let asset_tx = FinalizedTx::decode(&mut &instruction.data[..]).map_err(|error| {
        Error::ObjectLoadError {
            error,
            path: construct_path(db_dir.clone(), ON_CHAIN_DIR, &sender, &instruction_path),
        }
    })?;

    let mediator_account: MediatorAccount = load_object(
        db_dir.clone(),
        OFF_CHAIN_DIR,
        &mediator,
        SECRET_ACCOUNT_FILE,
    )?;

    let sender_account: PubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &sender.clone(),
        VALIDATED_PUBLIC_ACCOUNT_FILE,
    )?;

    let receiver_account: PubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &receiver.clone(),
        VALIDATED_PUBLIC_ACCOUNT_FILE,
    )?;

    timing!(
        "mediator.justify_tx.load_objects",
        justify_load_objects_timer,
        Instant::now()
    );

    // Justification.
    let justify_library_timer = Instant::now();
    let mediator = CtxMediator {};
    let asset_id = asset_id_from_ticker(&ticker).map_err(|error| Error::LibraryError { error })?;
    let justified_tx = mediator
        .justify_transaction(
            asset_tx.clone(),
            &mediator_account.encryption_key,
            &mediator_account.signing_key,
            &sender_account.content.memo.owner_sign_pub_key,
            &receiver_account.content.memo.owner_sign_pub_key,
            asset_id,
        )
        .map_err(|error| Error::LibraryError { error })?;

    timing!(
        "mediator.justify_tx.library",
        justify_library_timer,
        Instant::now()
    );

    let next_instruction;
    let justify_save_objects_timer = Instant::now();
    // If the `reject` flag is set, save the transaction as rejected.
    if reject {
        let rejected_state = TxState::Justification(TxSubstate::Rejected);
        next_instruction = CTXInstruction {
            data: asset_tx.encode().to_vec(),
            state: rejected_state,
        };

        save_object(
            db_dir.clone(),
            ON_CHAIN_DIR,
            &sender,
            &confidential_transaction_file(tx_id, rejected_state),
            &next_instruction,
        )?;
    } else {
        let new_state = TxState::Justification(TxSubstate::Started);
        // Save the updated_issuer_account, and the justified transaction.
        next_instruction = CTXInstruction {
            data: justified_tx.encode().to_vec(),
            state: new_state,
        };

        save_object(
            db_dir,
            ON_CHAIN_DIR,
            &sender,
            &confidential_transaction_file(tx_id, new_state),
            &next_instruction,
        )?;
    }

    timing!(
        "mediator.justify_tx.save_objects",
        justify_save_objects_timer,
        Instant::now()
    );

    Ok(())
}
