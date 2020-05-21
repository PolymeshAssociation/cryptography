//! mercat is the library that implements the confidential transactions
//! of the MERCAT, as defined in the section 6 of the whitepaper.

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
        range_proof,
        range_proof::{RangeProofFinalResponse, RangeProofInitialMessage},
        wellformedness_proof::{WellformednessFinalResponse, WellformednessInitialMessage},
        CipherText, ElgamalPublicKey, ElgamalSecretKey,
    },
    errors::{ErrorKind, Fallible},
};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use sp_application_crypto::sr25519;

// ---------------------- START: temporary types, move them to the proper location

// TODO move after CRYP-40
#[derive(Default, Clone)]
pub struct MembershipProofInitialMessage {}
#[derive(Default, Clone)]
pub struct MembershipProofFinalResponse {}

// ---------------------- END: temporary types, move them to other files

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
#[derive(Clone)]
pub struct EncryptionSecKey {
    pub key: ElgamalSecretKey,
}

impl From<ElgamalSecretKey> for EncryptionSecKey {
    fn from(key: ElgamalSecretKey) -> Self {
        Self { key }
    }
}

/// Holds ElGamal encryption keys.
#[derive(Clone)]
pub struct EncryptionKeys {
    pub pblc: EncryptionPubKey,
    pub scrt: EncryptionSecKey,
}

/// Holds the SR25519 signature scheme public key.
#[derive(Clone)]
pub struct SignaturePubKey {
    pub key: sr25519::Public,
}

impl From<sr25519::Public> for SignaturePubKey {
    fn from(key: sr25519::Public) -> Self {
        Self { key }
    }
}

/// Holds the SR25519 signature scheme public and private key pair.
#[derive(Clone)]
pub struct SignatureKeys {
    pub pair: sr25519::Pair,
}

/// Type alias for SR25519 signature.
pub type Signature = sr25519::Signature;

/// New type for Twisted ElGamal ciphertext of asset ids.
#[derive(Default, Debug, Copy, Clone, Serialize, Deserialize)]
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

/// Holds the non-interactive proofs of wellformedness, equivalent of L_enc of MERCAT paper.
#[derive(Default, Clone)]
pub struct WellformednessProof {
    init: WellformednessInitialMessage,
    response: WellformednessFinalResponse,
}

/// Holds the non-interactive proofs of correctness, equivalent of L_correct of MERCAT paper.
#[derive(Default, Clone)]
pub struct CorrectnessProof {
    init: CorrectnessInitialMessage,
    response: CorrectnessFinalResponse,
}

/// Holds the non-interactive proofs of membership, equivalent of L_member of MERCAT paper.
#[derive(Default, Clone)]
pub struct MembershipProof {
    init: MembershipProofInitialMessage,
    response: MembershipProofFinalResponse,
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
        let range = 32;
        InRangeProof::from(
            range_proof::prove_within_range(0, Scalar::one(), range)
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

/// Holds the account memo. TODO: more informative description!
#[derive(Clone)]
pub struct AccountMemo {
    pub owner_enc_pub_key: EncryptionPubKey,
    pub owner_sign_pub_key: SignaturePubKey,
    pub timestamp: std::time::Instant,
}

impl From<(EncryptionPubKey, SignaturePubKey)> for AccountMemo {
    fn from(pub_keys: (EncryptionPubKey, SignaturePubKey)) -> Self {
        AccountMemo {
            owner_enc_pub_key: pub_keys.0,
            owner_sign_pub_key: pub_keys.1,
            timestamp: std::time::Instant::now(),
        }
    }
}

/// Holds the public portion of an account which can be safely put on the chain.
#[derive(Clone)]
pub struct PubAccount {
    pub id: u32,
    pub enc_asset_id: EncryptedAssetId,
    pub enc_balance: EncryptedAmount,
    pub asset_wellformedness_proof: WellformednessProof,
    pub asset_membership_proof: MembershipProof,
    pub balance_correctness_proof: CorrectnessProof,
    pub memo: AccountMemo,
    pub sign: Signature,
}

// TODO Account creation is part of CRYP-61

// -------------------------------------------------------------------------------------
// -                               Transaction State                                   -
// -------------------------------------------------------------------------------------

/// Represents the three substates (started, verified, rejected) of a
/// confidential transaction state.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TxSubstate {
    /// The action on transaction has been taken but is not verified yet.
    Started,
    /// The action on transaction has been verified by validators.
    Verified,
    /// The action on transaction has failed the verification by validators.
    /// TODO: this ended up not being used. We need to disucss, how to handle it.
    Rejected,
}

/// Represents the two states (initialized, justified) of a
/// confidentional asset issuance transaction.
#[derive(Debug)]
pub enum AssetTxState {
    Initialization(TxSubstate),
    Justification(TxSubstate),
}

/// Represents the four states (initialized, justified, finalized, reversed) of a
/// confidentional transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidentialTxState {
    Initialization(TxSubstate),
    InitilaziationJustification(TxSubstate),
    Finalization(TxSubstate),
    Reversal(TxSubstate),
}

// -------------------------------------------------------------------------------------
// -                                 Asset Issuance                                    -
// -------------------------------------------------------------------------------------

/// Holds the public portion of an asset issuance transaction. This can be placed
/// on the chain.
pub struct PubAssetTxData {
    account_id: u32,
    enc_asset_id: EncryptedAssetId,
    enc_amount: EncryptedAmount,
    memo: AssetMemo,
    asset_id_equal_cipher_proof: CipherEqualSamePubKeyProof,
    balance_wellformedness_proof: WellformednessProof,
    balance_correctness_proof: CorrectnessProof,
    sig: Signature,
}

/// The interface for the confidential asset issuance transaction.
pub trait AssetTransactionIssuer {
    /// Initializes a confidentional asset issue transaction. Note that the returing
    /// values of this function contain sensitive information. Corresponds
    /// to `CreateAssetIssuanceTx` MERCAT whitepaper.
    fn initialize(
        &self,
        issr_enc_keys: (EncryptionPubKey, EncryptionSecKey),
        issr_sign_keys: SignatureKeys,
        amount: u32,
        issr_account: PubAccount,
        mdtr_pub_key: EncryptionPubKey,
        asset_id: u32, // deviation from the paper
    ) -> Fallible<(PubAssetTxData, AssetTxState)>;
}

pub trait AssetTransactionInitializeVerifier {
    /// Called by validators to verify the ZKP of the wellformedness of encrypted balance
    /// and to verify the signature.
    fn verify(
        &self,
        asset_tx: PubAssetTxData,
        state: AssetTxState,
        issr_sign_pub_key: SignaturePubKey,
    ) -> Fallible<AssetTxState>;
}

pub trait AssetTransactionMediator {
    /// Justifies and processes a confidential asset issue transaction. This method is called
    /// by mediator. Corresponds to `JustifyAssetTx` and `ProcessCTx` of MERCAT paper.
    /// If the trasaction is justified, it will be processed immediately.
    fn justify_and_process(
        &self,
        asset_tx: PubAssetTxData,
        issr_account: PubAccount,
        state: AssetTxState,
        mdtr_enc_keys: (EncryptionPubKey, EncryptionSecKey),
        mdtr_sign_keys: SignatureKeys,
        issr_pub_key: EncryptionPubKey,
        issr_acount: PubAccount,
    ) -> Fallible<(Signature, PubAccount, AssetTxState)>;
}

pub trait AssetTransactionFinalizeAndProcessVerifier {
    /// Called by validators to verify the justification and processing of the transaction.
    fn verify(
        &self,
        sig: Signature,
        issr_account: PubAccount,
        mdtr_sign_pub_key: SignaturePubKey,
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
}

/// Holds the proofs and memo of the confidential transaction sent by the sender.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PubInitConfidentialTxDataContent {
    pub amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
    pub non_neg_amount_proof: InRangeProof,
    pub enough_fund_proof: InRangeProof,
    pub memo: ConfidentialTxMemo,
    pub asset_id_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
    pub balance_refreshed_same_proof: CipherEqualSamePubKeyProof,
    pub asset_id_refreshed_same_proof: CipherEqualSamePubKeyProof,
}

impl PubInitConfidentialTxDataContent {
    pub fn to_bytes(&self) -> Fallible<Vec<u8>> {
        let mut encoded = vec![];
        encoded.extend(bincode::serialize(&self.memo).map_err(|_| ErrorKind::SerializationError)?);
        encoded.extend(
            bincode::serialize(&self.amount_equal_cipher_proof)
                .map_err(|_| ErrorKind::SerializationError)?,
        );
        encoded.extend(
            bincode::serialize(&self.non_neg_amount_proof)
                .map_err(|_| ErrorKind::SerializationError)?,
        );
        encoded.extend(
            bincode::serialize(&self.enough_fund_proof)
                .map_err(|_| ErrorKind::SerializationError)?,
        );
        encoded.extend(
            bincode::serialize(&self.asset_id_equal_cipher_proof)
                .map_err(|_| ErrorKind::SerializationError)?,
        );
        encoded.extend(
            bincode::serialize(&self.balance_refreshed_same_proof)
                .map_err(|_| ErrorKind::SerializationError)?,
        );
        encoded.extend(
            bincode::serialize(&self.asset_id_refreshed_same_proof)
                .map_err(|_| ErrorKind::SerializationError)?,
        );
        Ok(encoded)
    }
}

/// Wrapper for the initial transaction data and its signature.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PubInitConfidentialTxData {
    pub content: PubInitConfidentialTxDataContent,
    pub sig: Signature,
}

/// Holds the initial transaction data and the proof of equality of asset ids
/// prepared by the receiver.
#[derive(Debug)]
pub struct PubFinalConfidentialTxDataContent {
    pub init_data: PubInitConfidentialTxData,
    pub asset_id_equal_cipher_proof: CipherEqualSamePubKeyProof,
}

impl PubFinalConfidentialTxDataContent {
    pub fn to_bytes(&self) -> Fallible<Vec<u8>> {
        let mut encoded = vec![];
        encoded.extend(
            bincode::serialize(&self.init_data).map_err(|_| ErrorKind::SerializationError)?,
        );
        encoded.extend(
            bincode::serialize(&self.asset_id_equal_cipher_proof)
                .map_err(|_| ErrorKind::SerializationError)?,
        );
        Ok(encoded)
    }
}
/// Wrapper for the contents and the signature of the content sent by the
/// receiver of the transaction.
#[derive(Debug)]
pub struct PubFinalConfidentialTxData {
    pub content: PubFinalConfidentialTxDataContent,
    pub sig: Signature,
}

/// The interface for confidential transaction.
pub trait ConfidentialTransactionSender {
    /// This is called by the sender of a confidential transaction. The outputs
    /// can be safely placed on the chain. It corresponds to `CreateCTX` function of
    /// MERCAT paper.
    fn create(
        &self,
        sndr_enc_keys: EncryptionKeys,
        sndr_sign_keys: SignatureKeys,
        sndr_account: PubAccount,
        rcvr_pub_key: EncryptionPubKey,
        rcvr_account: PubAccount,
        asset_id: u32,
        amount: u32,
        rng: &mut StdRng,
    ) -> Fallible<(PubInitConfidentialTxData, ConfidentialTxState)>;
}

pub trait ConfidentialTransactionInitVerifier {
    /// This is called by the validators to verify the signature and some of the
    /// proofs of the initialized transaction.
    fn verify(
        &self,
        transaction: PubInitConfidentialTxData,
        sndr_account: PubAccount,
        state: ConfidentialTxState,
    ) -> Fallible<ConfidentialTxState>;
}

pub trait ConfidentialTransactionMediator {
    /// Justify the transaction by mediator.
    /// TODO: missing from the paper, will discuss and decide later.
    fn justify_init() -> Fallible<ConfidentialTxState>;
}

pub trait ConfidentialTransactionReceiver {
    /// This function is called the receiver of the transaction to finalize and process
    /// the transaction. It corresponds to `FinalizeCTX` and `ProcessCTX` functions
    /// of the MERCAT paper.
    fn finalize_and_process(
        &self,
        conf_tx_init_data: PubInitConfidentialTxData,
        rcvr_enc_keys: (EncryptionPubKey, EncryptionSecKey),
        rcvr_sign_keys: SignatureKeys,
        sndr_pub_key: EncryptionPubKey,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        enc_asset_id: EncryptedAssetId,
        amount: u32,
        state: ConfidentialTxState,
        rng: &mut StdRng,
    ) -> Fallible<(PubFinalConfidentialTxData, ConfidentialTxState)>;
}

pub trait ConfidentialTransactionFinalizeAndProcessVerifier {
    /// This is called by the validators to verify the finalized transaction.
    fn verify(
        &self,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        rcvr_sign_pub_key: SignaturePubKey,
        conf_tx_final_data: PubFinalConfidentialTxData,
        state: ConfidentialTxState,
    ) -> Fallible<ConfidentialTxState>;
}

// -------------------------------------------------------------------------------------
// -                         Reversal Confidential Transaction                         -
// -------------------------------------------------------------------------------------

/// Holds the public portion of the reversal transaction.
pub struct PubReverseConfidentialTxData {
    final_data: PubInitConfidentialTxData,
    memo: ReverseConfidentialTxMemo,
    sig: Signature,
}

/// Holds the memo for reversal of the confidential transaction sent by the mediator.
pub struct ReverseConfidentialTxMemo {
    enc_amount_using_rcvr: EncryptedAmount,
    enc_refreshed_amount: EncryptedAmount,
    enc_asset_id_using_rcvr: EncryptedAssetId,
}

pub trait ConfidentialTransactionReverseAndProcessMediator {
    /// This function is called by the mediator to reverse and process the reversal of
    /// the transaction. It corresponds to `ReverseCTX` of the MERCAT paper.
    fn create(
        &self,
        conf_tx_final_data: PubFinalConfidentialTxData,
        mdtr_enc_keys: EncryptionSecKey,
        mdtr_sign_keys: SignatureKeys,
        state: ConfidentialTxState,
    ) -> Fallible<(PubReverseConfidentialTxData, ConfidentialTxState)>;
}

pub trait ConfidentialTransactionReverseAndProcessVerifier {
    /// This function is called by validators to verify the reversal and processing of the
    /// reversal transaction.
    fn verify(
        &self,
        reverse_conf_tx_data: PubReverseConfidentialTxData,
        mdtr_sign_pub_key: SignaturePubKey,
        state: ConfidentialTxState,
    ) -> Fallible<ConfidentialTxState>;
}
