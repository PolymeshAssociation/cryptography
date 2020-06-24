//! mercat is the library that implements the confidential transactions
//! of the MERCAT, as defined in the section 6 of the whitepaper.

pub mod account;
pub mod asset;
pub mod conf_tx;

use crate::{
    asset_proofs::{
        ciphertext_refreshment_proof::{
            CipherTextRefreshmentFinalResponse, CipherTextRefreshmentInitialMessage,
        },
        correctness_proof::{CorrectnessFinalResponse, CorrectnessInitialMessage},
        encrypting_same_value_proof::{
            EncryptingSameValueFinalResponse, EncryptingSameValueInitialMessage,
        },
        membership_proof::{MembershipProofFinalResponse, MembershipProofInitialMessage},
        range_proof,
        range_proof::{RangeProofFinalResponse, RangeProofInitialMessage},
        wellformedness_proof::{WellformednessFinalResponse, WellformednessInitialMessage},
        CipherText, CommitmentWitness, ElgamalPublicKey, ElgamalSecretKey,
    },
    errors::{Error, ErrorKind, Fallible},
    AssetId, Balance,
};

use chrono::{DateTime, Utc};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::OsRng;
use rand_core::{CryptoRng, RngCore};
use schnorrkel::keys::{Keypair, PublicKey};
use serde::{Deserialize, Serialize};

use sp_std::{convert::From, vec::Vec};

// -------------------------------------------------------------------------------------
// -                                  Constants                                        -
// -------------------------------------------------------------------------------------

const EXPONENT: usize = 3; // TODO: change to 8. CRYP-112
const BASE: usize = 4;

// -------------------------------------------------------------------------------------
// -                                 New Type Def                                      -
// -------------------------------------------------------------------------------------

// Having separate types for encryption and signature will ensure that the keys used for encryption
// and signing are different.

/// Holds ElGamal encryption public key.
#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EncryptionPubKey {
    pub key: ElgamalPublicKey,
}

impl From<ElgamalPublicKey> for EncryptionPubKey {
    fn from(key: ElgamalPublicKey) -> Self {
        Self { key }
    }
}

/// Holds ElGamal encryption secret key.
#[derive(Clone, Debug)]
pub struct EncryptionSecKey {
    pub key: ElgamalSecretKey,
}

impl From<ElgamalSecretKey> for EncryptionSecKey {
    fn from(key: ElgamalSecretKey) -> Self {
        Self { key }
    }
}

/// Holds ElGamal encryption keys.
#[derive(Clone, Debug)]
pub struct EncryptionKeys {
    pub pblc: EncryptionPubKey,
    pub scrt: EncryptionSecKey,
}

/// Holds the SR25519 signature scheme public key.
pub type SigningPubKey = PublicKey;
pub type SigningKeys = Keypair;

pub type Signature = schnorrkel::sign::Signature;

/// New type for Twisted ElGamal ciphertext of asset ids.
#[derive(Default, Debug, Copy, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptedAssetId {
    pub cipher: CipherText,
}

impl From<CipherText> for EncryptedAssetId {
    fn from(cipher: CipherText) -> Self {
        Self { cipher }
    }
}

/// New type for Twisted ElGamal ciphertext of account amounts/balances.
#[derive(Default, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct EncryptedAmount {
    pub cipher: CipherText,
}

impl From<CipherText> for EncryptedAmount {
    fn from(cipher: CipherText) -> Self {
        Self { cipher }
    }
}

// TODO: move all these XXXProof to the proper file. CRYP-113

/// Holds the non-interactive proofs of wellformedness, equivalent of L_enc of MERCAT paper.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct WellformednessProof {
    init: WellformednessInitialMessage,
    response: WellformednessFinalResponse,
}

impl From<(WellformednessInitialMessage, WellformednessFinalResponse)> for WellformednessProof {
    fn from(pair: (WellformednessInitialMessage, WellformednessFinalResponse)) -> Self {
        Self {
            init: pair.0,
            response: pair.1,
        }
    }
}

/// Holds the non-interactive proofs of correctness, equivalent of L_correct of MERCAT paper.
#[derive(Default, Clone, Serialize, Deserialize, Debug)]
pub struct CorrectnessProof {
    init: CorrectnessInitialMessage,
    response: CorrectnessFinalResponse,
}

impl From<(CorrectnessInitialMessage, CorrectnessFinalResponse)> for CorrectnessProof {
    fn from(pair: (CorrectnessInitialMessage, CorrectnessFinalResponse)) -> Self {
        Self {
            init: pair.0,
            response: pair.1,
        }
    }
}

/// Holds the non-interactive proofs of membership, equivalent of L_member of MERCAT paper.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct MembershipProof {
    init: MembershipProofInitialMessage,
    response: MembershipProofFinalResponse,
    commitment: RistrettoPoint,
}

/// Holds the non-interactive range proofs, equivalent of L_range of MERCAT paper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InRangeProof {
    pub init: RangeProofInitialMessage,
    pub response: RangeProofFinalResponse,
    pub range: usize,
}

impl Default for InRangeProof {
    fn default() -> Self {
        let mut rng = OsRng::default();
        let range = 32;
        InRangeProof::from(
            range_proof::prove_within_range(0, Scalar::one(), range, &mut rng)
                .expect("This shouldn't happen."),
        )
    }
}

impl From<(RangeProofInitialMessage, RangeProofFinalResponse, usize)> for InRangeProof {
    fn from(proof: (RangeProofInitialMessage, RangeProofFinalResponse, usize)) -> Self {
        Self {
            init: proof.0,
            response: proof.1,
            range: proof.2,
        }
    }
}

/// Holds the non-interactive proofs of equality using different public keys, equivalent
/// of L_cipher of MERCAT paper.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct CipherEqualDifferentPubKeyProof {
    pub init: EncryptingSameValueInitialMessage,
    pub response: EncryptingSameValueFinalResponse,
}

impl
    From<(
        EncryptingSameValueInitialMessage,
        EncryptingSameValueFinalResponse,
    )> for CipherEqualDifferentPubKeyProof
{
    fn from(
        pair: (
            EncryptingSameValueInitialMessage,
            EncryptingSameValueFinalResponse,
        ),
    ) -> Self {
        Self {
            init: pair.0,
            response: pair.1,
        }
    }
}

/// Holds the non-interactive proofs of equality using different public keys, equivalent
/// of L_equal of MERCAT paper.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct CipherEqualSamePubKeyProof {
    pub init: CipherTextRefreshmentInitialMessage,
    pub response: CipherTextRefreshmentFinalResponse,
}

impl
    From<(
        CipherTextRefreshmentInitialMessage,
        CipherTextRefreshmentFinalResponse,
    )> for CipherEqualSamePubKeyProof
{
    fn from(
        pair: (
            CipherTextRefreshmentInitialMessage,
            CipherTextRefreshmentFinalResponse,
        ),
    ) -> Self {
        Self {
            init: pair.0,
            response: pair.1,
        }
    }
}

/// Asset memo holds the contents of an asset issuance transaction.
pub type AssetMemo = EncryptedAmount;

// -------------------------------------------------------------------------------------
// -                                    Account                                        -
// -------------------------------------------------------------------------------------

/// Holds the owner public keys and the creation date of an account.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AccountMemo {
    pub owner_enc_pub_key: EncryptionPubKey,
    pub owner_sign_pub_key: SigningPubKey,
    pub timestamp: DateTime<Utc>,
}

impl AccountMemo {
    pub fn new(owner_enc_pub_key: EncryptionPubKey, owner_sign_pub_key: SigningPubKey) -> Self {
        let timestamp = Utc::now();
        AccountMemo {
            owner_enc_pub_key,
            owner_sign_pub_key,
            timestamp,
        }
    }
}

/// Holds contents of the public portion of an account which can be safely put on the chain.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PubAccountContent {
    pub id: u32,
    pub enc_asset_id: EncryptedAssetId,
    pub enc_balance: EncryptedAmount,
    pub asset_wellformedness_proof: WellformednessProof,
    pub asset_membership_proof: MembershipProof,
    pub initial_balance_correctness_proof: CorrectnessProof,
    pub memo: AccountMemo,
}

impl PubAccountContent {
    pub fn to_bytes(&self) -> Fallible<Vec<u8>> {
        bincode::serialize(self).map_err(Error::from)
    }
}

/// Wrapper for the account content and signature.
#[derive(Clone, Debug)]
pub struct PubAccount {
    pub content: PubAccountContent,
    pub initial_sig: Signature,
}

/// Holds the secret keys and asset id of an account. This cannot be put on the change.
#[derive(Clone, Debug)]
pub struct SecAccount {
    pub enc_keys: EncryptionKeys,
    pub sign_keys: SigningKeys,
    pub asset_id: AssetId,
    pub asset_id_witness: CommitmentWitness,
}

/// Wrapper for both the secret and public account info
#[derive(Clone, Debug)]
pub struct Account {
    pub pblc: PubAccount,
    pub scrt: SecAccount,
}

impl Account {
    /// Utility method that can decrypt the the balance of an account.
    pub fn decrypt_balance(&self) -> Fallible<Balance> {
        let balance = self
            .scrt
            .enc_keys
            .scrt
            .key
            .decrypt(&self.pblc.content.enc_balance.cipher)?;

        Ok(Balance::from(balance))
    }
}

/// The interface for the account creation.
pub trait AccountCreater {
    /// Creates a public account for a user and initializes the balance to zero.
    /// Corresponds to `CreateAccount` method of the MERCAT paper.
    /// This function assumes that the given input `account_id` is unique.
    fn create_account<T: RngCore + CryptoRng>(
        &self,
        scrt_account: &SecAccount,
        valid_asset_ids: Vec<AssetId>,
        account_id: u32,
        rng: &mut T,
    ) -> Fallible<PubAccount>;
}

/// The interface for the verifying the account creation.
pub trait AccountCreaterVerifier {
    /// Called by the validators to ensure that the account was created correctly.
    fn verify(&self, account: &PubAccount, valid_asset_ids: &Vec<Scalar>) -> Fallible<()>;
}

// -------------------------------------------------------------------------------------
// -                               Transaction State                                   -
// -------------------------------------------------------------------------------------

/// Represents the three substates (started, verified, rejected) of a
/// confidential transaction state.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxSubstate {
    /// The action on transaction has been taken but is not verified yet.
    Started,
    /// The action on transaction has been verified by validators.
    Validated,
    /// The action on transaction has failed the verification by validators.
    Rejected,
}

/// Represents the two states (initialized, justified) of a
/// confidentional asset issuance transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetTxState {
    Initialization(TxSubstate),
    Justification(TxSubstate),
}

/// Represents the four states (initialized, justified, finalized, reversed) of a
/// confidentional transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidentialTxState {
    Initialization(TxSubstate),
    Finalization(TxSubstate),
    FinalizationJustification(TxSubstate),
    Reversal(TxSubstate),
}

// -------------------------------------------------------------------------------------
// -                                 Asset Issuance                                    -
// -------------------------------------------------------------------------------------

/// Holds the public portion of an asset issuance transaction after initialization.
/// This can be placed on the chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PubAssetTxDataContent {
    account_id: u32,
    enc_asset_id: EncryptedAssetId,
    enc_amount: EncryptedAmount,
    memo: AssetMemo,
    asset_id_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
    balance_wellformedness_proof: WellformednessProof,
    balance_correctness_proof: CorrectnessProof,
}

impl PubAssetTxDataContent {
    pub fn to_bytes(&self) -> Fallible<Vec<u8>> {
        bincode::serialize(self).map_err(Error::from)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PubAssetTxData {
    pub content: PubAssetTxDataContent,
    pub sig: Signature,
}

/// Holds the public portion of an asset issuance transaction after Justification.
/// This can be placed on the chain.
#[derive(Clone, Serialize, Deserialize)]
pub struct PubJustifiedAssetTxDataContent {
    pub tx_content: PubAssetTxData,
    pub state: AssetTxState,
}

impl PubJustifiedAssetTxDataContent {
    pub fn to_bytes(&self) -> Fallible<Vec<u8>> {
        bincode::serialize(self).map_err(Error::from)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PubJustifiedAssetTxData {
    pub content: PubJustifiedAssetTxDataContent,
    pub sig: Signature,
}

/// The interface for the confidential asset issuance transaction.
pub trait AssetTransactionIssuer {
    /// Initializes a confidentional asset issue transaction. Note that the returing
    /// values of this function contain sensitive information. Corresponds
    /// to `CreateAssetIssuanceTx` MERCAT whitepaper.
    fn initialize<T: RngCore + CryptoRng>(
        &self,
        issr_account_id: u32,
        issr_account: &SecAccount,
        mdtr_pub_key: &EncryptionPubKey,
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<(PubAssetTxData, AssetTxState)>;
}

pub trait AssetTransactionInitializeVerifier {
    /// Called by validators to verify the ZKP of the wellformedness of encrypted balance
    /// and to verify the signature.
    fn verify_initialization(
        &self,
        asset_tx: &PubAssetTxData,
        state: AssetTxState,
        issr_pub_account: &PubAccount,
        mdtr_enc_pub_key: &EncryptionPubKey,
    ) -> Fallible<AssetTxState>;
}

pub trait AssetTransactionMediator {
    /// Justifies and processes a confidential asset issue transaction. This method is called
    /// by mediator. Corresponds to `JustifyAssetTx` and `ProcessCTx` of MERCAT paper.
    /// If the trasaction is justified, it will be processed immediately and the updated account
    /// is returned.
    fn justify_and_process(
        &self,
        asset_tx: PubAssetTxData,
        issr_pub_account: &PubAccount,
        state: AssetTxState,
        mdtr_enc_keys: &EncryptionKeys,
        mdtr_sign_keys: &SigningKeys,
    ) -> Fallible<(PubJustifiedAssetTxData, PubAccount)>;
}

pub trait AssetTransactionFinalizeAndProcessVerifier {
    /// Called by validators to verify the justification and processing of the transaction.
    fn verify_justification(
        &self,
        asset_tx: &PubJustifiedAssetTxData,
        issr_account: &PubAccount,
        mdtr_sign_pub_key: &SigningPubKey,
    ) -> Fallible<AssetTxState>;
}

// -------------------------------------------------------------------------------------
// -                            Confidential Transaction                               -
// -------------------------------------------------------------------------------------

/// Holds the memo for confidential transaction sent by the sender.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialTxMemo {
    pub sndr_account_id: u32,
    pub rcvr_account_id: u32,
    pub enc_amount_using_sndr: EncryptedAmount,
    pub enc_amount_using_rcvr: EncryptedAmount,
    pub sndr_pub_key: EncryptionPubKey,
    pub rcvr_pub_key: EncryptionPubKey,
    pub refreshed_enc_balance: EncryptedAmount,
    pub refreshed_enc_asset_id: EncryptedAssetId,
    pub enc_asset_id_using_rcvr: EncryptedAssetId,
    pub enc_asset_id_for_mdtr: EncryptedAssetId,
    pub enc_amount_for_mdtr: EncryptedAmount,
}

/// Holds the proofs and memo of the confidential transaction sent by the sender.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PubInitConfidentialTxDataContent {
    pub amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
    pub non_neg_amount_proof: InRangeProof,
    pub enough_fund_proof: InRangeProof,
    pub memo: ConfidentialTxMemo,
    pub asset_id_equal_cipher_with_sndr_rcvr_keys_proof: CipherEqualDifferentPubKeyProof,
    pub balance_refreshed_same_proof: CipherEqualSamePubKeyProof,
    pub asset_id_refreshed_same_proof: CipherEqualSamePubKeyProof,
    pub asset_id_correctness_proof: CorrectnessProof,
    pub amount_correctness_proof: CorrectnessProof,
}

impl PubInitConfidentialTxDataContent {
    pub fn to_bytes(&self) -> Fallible<Vec<u8>> {
        bincode::serialize(self).map_err(Error::from)
    }
}

/// Wrapper for the initial transaction data and its signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubInitConfidentialTxData {
    pub content: PubInitConfidentialTxDataContent,
    pub sig: Signature,
}

/// Holds the initial transaction data and the proof of equality of asset ids
/// prepared by the receiver.
#[derive(Debug, Serialize, Deserialize)]
pub struct PubFinalConfidentialTxDataContent {
    pub init_data: PubInitConfidentialTxData,
    pub asset_id_from_sndr_equal_to_rcvr_proof: CipherEqualSamePubKeyProof,
}

impl PubFinalConfidentialTxDataContent {
    pub fn to_bytes(&self) -> Fallible<Vec<u8>> {
        bincode::serialize(self).map_err(Error::from)
    }
}

/// Wrapper for the contents and the signature of the content sent by the
/// receiver of the transaction.
#[derive(Debug, Serialize, Deserialize)]
pub struct PubFinalConfidentialTxData {
    pub content: PubFinalConfidentialTxDataContent,
    pub sig: Signature,
}

impl PubFinalConfidentialTxData {
    pub fn to_bytes(&self) -> Fallible<Vec<u8>> {
        bincode::serialize(self).map_err(|_| ErrorKind::SerializationError.into())
    }
}

/// Wrapper for the contents and the signature of the justified and finalized
/// transaction.
#[derive(Debug)]
pub struct JustifiedPubFinalConfidentialTxData {
    pub conf_tx_final_data: PubFinalConfidentialTxData,
    pub sig: Signature,
}

/// The interface for confidential transaction.
pub trait ConfidentialTransactionSender {
    /// This is called by the sender of a confidential transaction. The outputs
    /// can be safely placed on the chain. It corresponds to `CreateCTX` function of
    /// MERCAT paper.
    fn create_transaction<T: RngCore + CryptoRng>(
        &self,
        sndr_account: &Account,
        rcvr_pub_account: &PubAccount,
        mdtr_pub_key: &EncryptionPubKey,
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<(PubInitConfidentialTxData, ConfidentialTxState)>;
}

pub trait ConfidentialTransactionInitVerifier {
    /// This is called by the validators to verify the signature and some of the
    /// proofs of the initialized transaction.
    fn verify(
        &self,
        transaction: &PubInitConfidentialTxData,
        sndr_account: &PubAccount,
        state: ConfidentialTxState,
    ) -> Fallible<ConfidentialTxState>;
}

pub trait ConfidentialTransactionMediator {
    /// Justify the transaction by mediator.
    fn justify(
        &self,
        conf_tx_final_data: PubFinalConfidentialTxData,
        state: ConfidentialTxState,
        mdtr_sec_account: &SecAccount,
        // NOTE: without this, decryption takes a very long time. Since asset id to scalar takes the hash of the asset id array.
        asset_id_hint: AssetId,
    ) -> Fallible<(JustifiedPubFinalConfidentialTxData, ConfidentialTxState)>;
}

pub trait ConfidentialTransactionMediatorVerifier {
    /// This is called by the validators to verify the justification phase which was done by the mediator.
    fn verify(
        &self,
        conf_tx_justified_final_data: &JustifiedPubFinalConfidentialTxData,
        mdtr_sign_pub_key: &SigningPubKey,
        state: ConfidentialTxState,
    ) -> Fallible<ConfidentialTxState>;
}

pub trait ConfidentialTransactionReceiver {
    /// This function is called the receiver of the transaction to finalize and process
    /// the transaction. It corresponds to `FinalizeCTX` and `ProcessCTX` functions
    /// of the MERCAT paper.
    fn finalize_and_process<T: RngCore + CryptoRng>(
        &self,
        conf_tx_init_data: PubInitConfidentialTxData,
        sndr_pub_account: &PubAccount,
        rcvr_account: Account,
        enc_asset_id: EncryptedAssetId,
        amount: Balance,
        state: ConfidentialTxState,
        rng: &mut T,
    ) -> Fallible<(PubFinalConfidentialTxData, ConfidentialTxState)>;
}

pub trait ConfidentialTransactionFinalizeAndProcessVerifier {
    /// This is called by the validators to verify the finalized transaction.
    fn verify(
        &self,
        sndr_account: &PubAccount,
        rcvr_account: &PubAccount,
        rcvr_sign_pub_key: SigningPubKey,
        conf_tx_final_data: &PubFinalConfidentialTxData,
        state: ConfidentialTxState,
    ) -> Fallible<ConfidentialTxState>;
}

// -------------------------------------------------------------------------------------
// -                         Reversal Confidential Transaction                         -
// -------------------------------------------------------------------------------------

/// Holds the public portion of the reversal transaction.
pub struct PubReverseConfidentialTxData {
    _final_data: PubInitConfidentialTxData,
    _memo: ReverseConfidentialTxMemo,
    _sig: Signature,
}

/// Holds the memo for reversal of the confidential transaction sent by the mediator.
pub struct ReverseConfidentialTxMemo {
    _enc_amount_using_rcvr: EncryptedAmount,
    _enc_refreshed_amount: EncryptedAmount,
    _enc_asset_id_using_rcvr: EncryptedAssetId,
}

pub trait ConfidentialTransactionReverseAndProcessMediator {
    /// This function is called by the mediator to reverse and process the reversal of
    /// the transaction. It corresponds to `ReverseCTX` of the MERCAT paper.
    fn create(
        &self,
        conf_tx_final_data: PubFinalConfidentialTxData,
        mdtr_enc_keys: EncryptionSecKey,
        mdtr_sign_keys: SigningKeys,
        state: ConfidentialTxState,
    ) -> Fallible<(PubReverseConfidentialTxData, ConfidentialTxState)>;
}

pub trait ConfidentialTransactionReverseAndProcessVerifier {
    /// This function is called by validators to verify the reversal and processing of the
    /// reversal transaction.
    fn verify(
        &self,
        reverse_conf_tx_data: PubReverseConfidentialTxData,
        mdtr_sign_pub_key: SigningPubKey,
        state: ConfidentialTxState,
    ) -> Fallible<ConfidentialTxState>;
}
