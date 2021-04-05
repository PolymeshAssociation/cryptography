use crate::{
    create_rng_from_seed, errors::Error, save_object, AUDITOR_PUBLIC_ACCOUNT_FILE, OFF_CHAIN_DIR,
    ON_CHAIN_DIR, SECRET_ACCOUNT_FILE,
};
use codec::Encode;
use cryptography_core::asset_proofs::ElgamalSecretKey;
use curve25519_dalek::scalar::Scalar;
use log::info;
use mercat::{AuditorAccount, EncryptionKeys, EncryptionPubKey};
use metrics::timing;
use rand::{CryptoRng, RngCore};
use std::{path::PathBuf, time::Instant};

fn generate_auditors_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
    auditor_id: u32,
) -> ((u32, EncryptionPubKey), AuditorAccount) {
    let auditor_elg_secret_key = ElgamalSecretKey::new(Scalar::random(rng));
    let auditor_enc_key = EncryptionKeys {
        public: auditor_elg_secret_key.get_public_key(),
        secret: auditor_elg_secret_key,
    };

    (
        (auditor_id, auditor_enc_key.public),
        AuditorAccount {
            encryption_key: auditor_enc_key,
            auditor_id,
        },
    )
}
pub fn process_create_auditor(
    seed: String,
    db_dir: PathBuf,
    user: String,
    auditor_id: u32,
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
