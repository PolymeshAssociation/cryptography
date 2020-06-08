//! The MERCAT's asset issuance implementation.
//!
use crate::{
    asset_proofs::{
        correctness_proof::CorrectnessProverAwaitingChallenge,
        encrypting_same_value_proof::EncryptingSameValueProverAwaitingChallenge,
        encrypting_same_value_proof::EncryptingSameValueVerifier,
        encryption_proofs::single_property_prover,
        encryption_proofs::single_property_verifier,
        wellformedness_proof::{WellformednessProverAwaitingChallenge, WellformednessVerifier},
    },
    errors::{ErrorKind, Fallible},
    mercat::{
        AssetMemo, AssetTransactionInitializeVerifier, AssetTransactionIssuer, AssetTxState,
        CipherEqualDifferentPubKeyProof, CorrectnessProof, EncryptionPubKey, PubAccount,
        PubAssetTxData, PubAssetTxDataContent, SecAccount, TxSubstate, WellformednessProof,
    },
    Balance,
};

use bulletproofs::PedersenGens;
use lazy_static::lazy_static;
use rand::rngs::StdRng;
use schnorrkel::{context::SigningContext, signing_context};
use zeroize::Zeroizing;

lazy_static! {
    static ref SIG_CTXT: SigningContext = signing_context(b"mercat/assert");
}

/// Helper function to verify the proofs on an asset initialization transaction.
fn asset_issuance_init_verify(
    asset_tx: &PubAssetTxData,
    issr_pub_account: &PubAccount,
    mdtr_enc_pub_key: &EncryptionPubKey,
) -> Fallible<()> {
    let gens = PedersenGens::default();

    // Verify the signature on the transaction.
    let message = asset_tx.content.to_bytes()?;
    issr_pub_account
        .content
        .memo
        .owner_sign_pub_key
        .verify(SIG_CTXT.bytes(&message), &asset_tx.sig)
        .map_err(|_| ErrorKind::SignatureValidationFailure)?;

    // Verify the proof of encrypting the same asset type as the account type.
    single_property_verifier(
        &EncryptingSameValueVerifier {
            pub_key1: issr_pub_account.content.memo.owner_enc_pub_key.key,
            pub_key2: mdtr_enc_pub_key.key,
            cipher1: issr_pub_account.content.enc_asset_id.cipher,
            cipher2: asset_tx.content.enc_asset_id.cipher,
            pc_gens: &gens,
        },
        asset_tx.content.asset_id_equal_cipher_proof.init,
        asset_tx.content.asset_id_equal_cipher_proof.response,
    )?;

    // Verify the proof of memo's wellformedness.
    single_property_verifier(
        &WellformednessVerifier {
            pub_key: issr_pub_account.content.memo.owner_enc_pub_key.key,
            cipher: asset_tx.content.memo.cipher,
            pc_gens: &gens,
        },
        asset_tx.content.balance_wellformedness_proof.init,
        asset_tx.content.balance_wellformedness_proof.response,
    )?;

    Ok(())
}

// -------------------------------------------------------------------------------------
// -                                    Issuer                                         -
// -------------------------------------------------------------------------------------

/// The confidential transaction issuer issues an asset for an issuer account, and
/// encrypts the metadata to the mediator's public key.
pub struct CtxIssuer {}

impl AssetTransactionIssuer for CtxIssuer {
    fn initialize(
        &self,
        issr_account_id: u32,
        issr_account: &SecAccount,
        mdtr_pub_key: &EncryptionPubKey,
        amount: Balance,
        rng: &mut StdRng,
    ) -> Fallible<(PubAssetTxData, AssetTxState)> {
        let gens = PedersenGens::default();

        // Encrypt the asset_id with mediator's public key.
        let mdtr_enc_asset_id = mdtr_pub_key.key.encrypt(&issr_account.asset_id_witness);

        // Encrypt the balance issued to mediator's public key.
        let (_, mdtr_enc_amount) = mdtr_pub_key.key.encrypt_value(amount.into(), rng);

        // Encrypt the balance to issuer's public key (memo).
        let (issr_amount_witness, issr_enc_amount) = issr_account
            .enc_keys
            .pblc
            .key
            .encrypt_value(amount.into(), rng);
        let memo = AssetMemo::from(issr_enc_amount);

        // Proof of encrypting the same asset type as the account type.
        let same_asset_id_cipher_proof =
            CipherEqualDifferentPubKeyProof::from(single_property_prover(
                EncryptingSameValueProverAwaitingChallenge {
                    pub_key1: issr_account.enc_keys.pblc.key,
                    pub_key2: mdtr_pub_key.key,
                    w: Zeroizing::new(issr_account.asset_id_witness.clone()),
                    pc_gens: &gens,
                },
                rng,
            )?);

        // Proof of memo's wellformedness.
        let memo_wellformedness_proof = WellformednessProof::from(single_property_prover(
            WellformednessProverAwaitingChallenge {
                pub_key: issr_account.enc_keys.pblc.key,
                w: Zeroizing::new(issr_amount_witness.clone()),
                pc_gens: &gens,
            },
            rng,
        )?);

        // Proof of memo's correctness.
        let memo_correctness_proof = CorrectnessProof::from(single_property_prover(
            CorrectnessProverAwaitingChallenge {
                pub_key: issr_account.enc_keys.pblc.key,
                w: issr_amount_witness,
                pc_gens: &gens,
            },
            rng,
        )?);

        // Bundle the issuance data.
        let content = PubAssetTxDataContent {
            account_id: issr_account_id,
            enc_asset_id: mdtr_enc_asset_id.into(),
            enc_amount: mdtr_enc_amount.into(),
            memo: memo,
            asset_id_equal_cipher_proof: same_asset_id_cipher_proof,
            balance_wellformedness_proof: memo_wellformedness_proof,
            balance_correctness_proof: memo_correctness_proof,
        };

        // Sign the issuance content.
        let message = content.to_bytes()?;
        let sig = issr_account.sign_keys.sign(SIG_CTXT.bytes(&message));

        Ok((
            PubAssetTxData { content, sig },
            AssetTxState::Initialization(TxSubstate::Started),
        ))
    }
}

// -------------------------------------------------------------------------------------
// -                                    Validator                                      -
// -------------------------------------------------------------------------------------

pub struct AssetTxIssueValidator {}

impl AssetTransactionInitializeVerifier for AssetTxIssueValidator {
    /// Called by validators to verify the ZKP of the wellformedness of encrypted balance
    /// and to verify the signature.
    fn verify(
        &self,
        asset_tx: &PubAssetTxData,
        state: AssetTxState,
        issr_pub_account: &PubAccount,
        mdtr_enc_pub_key: &EncryptionPubKey,
    ) -> Fallible<AssetTxState> {
        // Validate the state.
        ensure!(
            state == AssetTxState::Initialization(TxSubstate::Started),
            ErrorKind::InvalidPreviousAssetTransactionState { state }
        );

        asset_issuance_init_verify(asset_tx, issr_pub_account, mdtr_enc_pub_key)?;

        Ok(AssetTxState::Initialization(TxSubstate::Validated))
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::{
        asset_proofs::{CommitmentWitness, ElgamalSecretKey},
        mercat::{
            AccountMemo, CorrectnessProof, EncryptedAmount, EncryptedAssetId, EncryptionKeys,
            EncryptionPubKey, MembershipProof, PubAccountContent, SecAccount,
        },
        AssetId,
    };
    use curve25519_dalek::scalar::Scalar;
    use rand::SeedableRng;
    use wasm_bindgen_test::*;

    #[test]
    #[wasm_bindgen_test]
    fn asset_issuance_and_validation() {
        // ----------------------- setup
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Generate keys for the issuer.
        let issuer_elg_secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let issuer_enc_key = EncryptionKeys {
            pblc: issuer_elg_secret_key.get_public_key().into(),
            scrt: issuer_elg_secret_key.into(),
        };
        let sign_keys = schnorrkel::Keypair::generate_with(&mut rng);
        let asset_id = AssetId::from(1);

        let issuer_secret_account = SecAccount {
            enc_keys: issuer_enc_key.clone(),
            sign_keys: sign_keys.clone(),
            asset_id: asset_id.clone(),
            asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
        };

        let pub_account_enc_asset_id = EncryptedAssetId::from(
            issuer_enc_key
                .pblc
                .key
                .encrypt(&issuer_secret_account.asset_id_witness),
        );

        // Note that we use default proof values since we don't reverify these proofs during asset issuance.
        // Asset issuance also doesn't concern with the current account balance at the moment.
        let issuer_public_account = PubAccount {
            content: PubAccountContent {
                id: 1,
                enc_asset_id: pub_account_enc_asset_id,
                enc_balance: EncryptedAmount::default(),
                asset_wellformedness_proof: WellformednessProof::default(),
                asset_membership_proof: MembershipProof::default(),
                balance_correctness_proof: CorrectnessProof::default(),
                memo: AccountMemo::new(issuer_enc_key.pblc, sign_keys.public.into()),
            },
            sig: Default::default(),
        };

        // Generate keys for the mediator.
        let mediator_enc_pub_key: EncryptionPubKey =
            ElgamalSecretKey::new(Scalar::random(&mut rng))
                .get_public_key()
                .into();

        // Positive tests.
        let issuer = CtxIssuer {};
        let (asset_tx, state) = issuer
            .initialize(
                1234u32,
                &issuer_secret_account,
                &mediator_enc_pub_key,
                20u32.into(),
                &mut rng,
            )
            .unwrap();

        let validator = AssetTxIssueValidator {};
        let result = validator
            .verify(
                &asset_tx,
                state,
                &issuer_public_account,
                &mediator_enc_pub_key,
            )
            .unwrap();
        assert_eq!(result, AssetTxState::Initialization(TxSubstate::Validated));
    }
}
