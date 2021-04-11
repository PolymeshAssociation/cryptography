use crate::{
    asset_transaction_audit_result_file, asset_transaction_file,
    confidential_transaction_audit_result_file, confidential_transaction_file, construct_path,
    create_rng_from_seed, errors::Error, load_object, load_transaction_names, save_object,
    user_public_account_file, AuditResult, InitializedAssetTx, OrderedAssetInstruction,
    OrderedPubAccount, TransferInstruction, TxNameIdInfo, AUDITOR_PUBLIC_ACCOUNT_FILE,
    COMMON_OBJECTS_DIR, OFF_CHAIN_DIR, ON_CHAIN_DIR, SECRET_ACCOUNT_FILE,
};
use codec::{Decode, Encode};
use cryptography_core::asset_proofs::ElgamalSecretKey;
use curve25519_dalek::scalar::Scalar;
use log::info;
use mercat::{
    asset::AssetAuditor, transaction::CtxAuditor, AssetTransactionAuditor, AssetTxState,
    AuditorAccount, AuditorPubAccount, EncryptionKeys, JustifiedTransferTx,
    TransferTransactionAuditor, TransferTxState, TxSubstate,
};
use metrics::timing;
use rand::{CryptoRng, RngCore};
use std::{path::PathBuf, time::Instant};

fn generate_auditors_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
    auditor_id: u8,
) -> (AuditorPubAccount, AuditorAccount) {
    let auditor_elg_secret_key = ElgamalSecretKey::new(Scalar::random(rng));
    let auditor_enc_key = EncryptionKeys {
        public: auditor_elg_secret_key.get_public_key(),
        secret: auditor_elg_secret_key,
    };

    (
        AuditorPubAccount {
            auditor_id: [auditor_id; 32],
            encryption_public_key: auditor_enc_key.public,
        },
        AuditorAccount {
            encryption_key: auditor_enc_key,
            auditor_id: [auditor_id; 32],
        },
    )
}

pub fn process_create_auditor(
    seed: String,
    db_dir: PathBuf,
    user: String,
    auditor_id: u8,
) -> Result<(), Error> {
    // Setup the rng.
    let mut rng = create_rng_from_seed(Some(seed))?;

    // Generate keys for the auditor.
    let auditor_key_gen_timer = Instant::now();
    let (public_account, private_account) = generate_auditors_keys(&mut rng, auditor_id);
    timing!(
        "auditor.key_gen",
        auditor_key_gen_timer,
        Instant::now(),
        "tx_id" => "N/A"
    );

    let auditor_save_keys_timer = Instant::now();
    save_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &user,
        AUDITOR_PUBLIC_ACCOUNT_FILE,
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
        "CLI log: auditor keys as base64:\n{}\n",
        base64::encode(public_account.encode())
    );
    timing!(
        "auditor.save_keys",
        auditor_save_keys_timer,
        Instant::now(),
        "tx_id" => "N/A"
    );

    Ok(())
}

pub fn process_audit(auditor: String, tx_name: String, db_dir: PathBuf) -> Result<(), Error> {
    let tx_info = load_transaction_names(db_dir.clone())[&tx_name].clone();
    match tx_info {
        TxNameIdInfo::Asset(tx_asset_info) => {
            let instruction_path = asset_transaction_file(
                tx_asset_info.tx_id,
                &tx_asset_info.issuer,
                AssetTxState::Initialization(TxSubstate::Started),
            );
            let instruction: OrderedAssetInstruction = load_object(
                db_dir.clone(),
                ON_CHAIN_DIR,
                COMMON_OBJECTS_DIR,
                &instruction_path,
            )?;

            let issuer_ordered_pub_account: OrderedPubAccount = load_object(
                db_dir.clone(),
                ON_CHAIN_DIR,
                &tx_asset_info.issuer,
                &user_public_account_file(&tx_asset_info.ticker),
            )?;

            let auditor_account: AuditorAccount =
                load_object(db_dir.clone(), OFF_CHAIN_DIR, &auditor, SECRET_ACCOUNT_FILE)?;

            let asset_tx =
                InitializedAssetTx::decode(&mut &instruction.data[..]).map_err(|error| {
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

            let result = AssetAuditor {}.audit_asset_transaction(
                &asset_tx,
                &issuer_ordered_pub_account.pub_account,
                &auditor_account,
            );

            let audit_result_path = asset_transaction_audit_result_file(
                tx_asset_info.tx_id,
                &tx_asset_info.issuer,
                AssetTxState::Initialization(TxSubstate::Started),
            );
            let audit_result = AuditResult::from(&result);
            save_object(
                db_dir,
                ON_CHAIN_DIR,
                &auditor,
                &audit_result_path,
                &serde_json::to_string(&(tx_name, audit_result))
                    .map_err(|_| Error::SerializeError)?,
            )?;

            result.map_err(|error| Error::LibraryError { error })
        }
        TxNameIdInfo::Transfer(tx_transfer_info) => {
            let instruction_path = confidential_transaction_file(
                tx_transfer_info.tx_id,
                &tx_transfer_info.sender,
                TransferTxState::Justification(TxSubstate::Validated),
            );
            let instruction: TransferInstruction = load_object(
                db_dir.clone(),
                ON_CHAIN_DIR,
                COMMON_OBJECTS_DIR,
                &instruction_path,
            )?;

            let sender_ordered_pub_account: OrderedPubAccount = load_object(
                db_dir.clone(),
                ON_CHAIN_DIR,
                &tx_transfer_info.sender,
                &user_public_account_file(&tx_transfer_info.ticker),
            )?;
            let receiver_ordered_pub_account: OrderedPubAccount = load_object(
                db_dir.clone(),
                ON_CHAIN_DIR,
                &tx_transfer_info.receiver,
                &user_public_account_file(&tx_transfer_info.ticker),
            )?;

            let auditor_account: AuditorAccount =
                load_object(db_dir.clone(), OFF_CHAIN_DIR, &auditor, SECRET_ACCOUNT_FILE)?;

            let asset_tx =
                JustifiedTransferTx::decode(&mut &instruction.data[..]).map_err(|error| {
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

            let result = CtxAuditor {}.audit_transaction(
                &asset_tx,
                &sender_ordered_pub_account.pub_account,
                &receiver_ordered_pub_account.pub_account,
                &auditor_account,
            );

            let audit_result_path = confidential_transaction_audit_result_file(
                tx_transfer_info.tx_id,
                &tx_transfer_info.sender,
                TransferTxState::Justification(TxSubstate::Validated),
            );
            let audit_result = AuditResult::from(&result);
            save_object(
                db_dir,
                ON_CHAIN_DIR,
                &auditor,
                &audit_result_path,
                &serde_json::to_string(&(tx_name, audit_result))
                    .map_err(|_| Error::SerializeError)?,
            )?;

            result.map_err(|error| Error::LibraryError { error })
        }
    }
}
