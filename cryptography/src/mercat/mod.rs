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
        wellformedness_proof::{WellformednessFinalResponse, WellformednessInitialMessage},
        CipherText, ElgamalPublicKey, ElgamalSecretKey,
    },
    errors::Fallible,
};
use bulletproofs::RangeProof;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use rand::rngs::StdRng;

// ---------------------- START: temporary types, move them to the proper location

// Having separate types for encryption and signature will ensure that the keys used for encryption
// and signing are different.
#[derive(Default, Debug, Clone)]
pub struct EncryptionPubKey {
    pub key: ElgamalPublicKey,
}

impl From<ElgamalPublicKey> for EncryptionPubKey {
    fn from(key: ElgamalPublicKey) -> Self {
        Self { key }
    }
}

#[derive(Clone)]
pub struct EncryptionSecKey {
    pub key: ElgamalSecretKey,
}

impl From<ElgamalSecretKey> for EncryptionSecKey {
    fn from(key: ElgamalSecretKey) -> Self {
        Self { key }
    }
}

pub struct EncryptionKeys {
    pub pblc: EncryptionPubKey,
    pub scrt: EncryptionSecKey,
}
// TODO experimenting with the API, remove once finalized
//impl EncryptionKeys {
//    pub fn pblc(&self) -> ElgamalPublicKey {
//        self.pblc.key()
//    }
//    pub fn scrt(&self) -> ElgamalSecretKey {
//        self.scrt.key()
//    }
//}

type SignaturePubKey = EncryptionPubKey;
type SignatureSecKey = EncryptionSecKey;

pub struct SignatureKeys {
    pub pblc: SignaturePubKey,
    pub scrt: SignatureSecKey,
}

// TODO move after CRYP-40
#[derive(Default)]
pub struct MembershipProofInitialMessage {}
#[derive(Default)]
pub struct MembershipProofFinalResponse {}

// TODO move after CRYP-71
#[derive(Default, Debug)]
pub struct Signature {}

// ---------------------- END: temporary types, move them to other files

// ---------------- type aliases for better code readability

/// Type alias for Twisted Elgamal ciphertext of asset ids.
pub type EncryptedAssetId = CipherText;

/// Type alias for Twisted Elgamal ciphertext of account amounts/balances.
pub type EncryptedAmount = CipherText;

/// Type alias for the tuple of initial message and final response of a non-interactive ZKP for wellformedness.
#[derive(Default)]
pub struct WellformednessProof {
    init: WellformednessInitialMessage,
    response: WellformednessFinalResponse,
}

/// Type alias for the tuple of initial message and final response of a non-interactive ZKP for correctness.
#[derive(Default)]
pub struct CorrectnessProof {
    init: CorrectnessInitialMessage,
    response: CorrectnessFinalResponse,
}

/// Type alias for the tuple of initial message and final response of a non-interactive ZKP for membership.
#[derive(Default)]
pub struct MembershipProof {
    init: MembershipProofInitialMessage,
    response: MembershipProofFinalResponse,
}

/// Type alias for the tuple of initial message and final response of a non-interactive ZKP for range.
#[derive(Debug)]
pub struct InRangeProof {
    pub proof: RangeProof,
    pub commitment: CompressedRistretto,
    pub range: usize,
}

impl Default for InRangeProof {
    fn default() -> Self {
        let range = 32;
        let (proof, commitment) = range_proof::prove_within_range(0, Scalar::one(), range)
            .expect("This shouldn't happen.");
        InRangeProof {
            proof: proof,
            commitment: commitment,
            range: range,
        }
    }
}

/// TODO: update the documentation and remove the type alias
/// Type alias for the tuple of initial message and final response of a non-interactive ZKP for cipher
/// equality under different public key.
#[derive(Default, Debug)]
pub struct CipherEqualDifferentPubKeyProof {
    pub init: EncryptingSameValueInitialMessage,
    pub response: EncryptingSameValueFinalResponse,
}

impl CipherEqualDifferentPubKeyProof {
    pub fn new(
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

/// TODO
#[derive(Default, Debug)]
pub struct CipherEqualSamePubKeyProof {
    pub init: CipherTextRefreshmentInitialMessage,
    pub response: CipherTextRefreshmentFinalResponse,
}

impl CipherEqualSamePubKeyProof {
    pub fn new(
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

/// Asset memo. TODO: more informative description!
pub type AssetMemo = EncryptedAmount;

// ------------------ account

/// Holds the account memo. TODO: more informative description!
pub struct AccountMemo {
    pub owner_pub_key: EncryptionPubKey,
    pub timestamp: std::time::Instant,
}

impl From<EncryptionPubKey> for AccountMemo {
    fn from(owner_pub_key: EncryptionPubKey) -> Self {
        AccountMemo {
            owner_pub_key,
            timestamp: std::time::Instant::now(),
        }
    }
}

/// Holds the public portion of an account which can be safely put on the chain.
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

// ----------------- States

/// Represents the three substates (started, verified, rejected) of a
/// confidential transaction state.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TxSubstate {
    /// The action on transaction has been taken but is not verified yet.
    Started,
    /// The action on transaction has been verified by validators.
    Verified,
    /// The action on transaction has failed the verification by validators.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfidentialTxState {
    Initialization(TxSubstate),
    InitilaziationJustification(TxSubstate),
    Finalization(TxSubstate),
    Reversal(TxSubstate),
}

// ----------------------------- Asset Issuance

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
        issr_sign_key: SignatureSecKey,
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
        mdtr_sign_key: SignatureSecKey,
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

// ----------------------------- Confidential Transaction

/// Holds the memo for confidential transaction sent by the sender.
#[derive(Default, Debug)]
pub struct ConfidentialTxMemo {
    pub sndr_account_id: u32,
    pub rcvr_account_id: u32,
    pub enc_amount_using_sndr: EncryptedAmount,
    pub enc_amount_using_rcvr: EncryptedAmount,
    pub sndr_pub_key: EncryptionPubKey,
    pub rcvr_pub_key: EncryptionPubKey,
    pub enc_refreshed_balance: EncryptedAmount,
    pub enc_asset_id_using_rcvr: EncryptedAssetId,
}

/// Holds the memo for reversal of the confidential transaction sent by the mediator.
pub struct ReverseConfidentialTxMemo {
    enc_amount_using_rcvr: EncryptedAmount,
    enc_refreshed_amount: EncryptedAmount,
    enc_asset_id_using_rcvr: EncryptedAssetId,
}

/// Holds the public portion of the confidential transaction sent by the sender.
#[derive(Default, Debug)]
pub struct PubInitConfidentialTxData {
    pub amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
    pub non_neg_amount_proof: InRangeProof,
    pub enough_fund_proof: InRangeProof,
    pub memo: ConfidentialTxMemo,
    pub asset_id_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
    pub balance_refreshed_same_proof: CipherEqualSamePubKeyProof,
    pub sig: Signature,
}

/// Holds the public portion of the confidential transaction that is finalized by
/// receiver.
#[derive(Debug)]
pub struct PubFinalConfidentialTxData {
    pub init_data: PubInitConfidentialTxData,
    pub asset_id_equal_cipher_proof: CipherEqualSamePubKeyProof,
    pub sig: Signature,
}

/// Holds the public portion of the reversal transaction.
pub struct PubReverseConfidentialTxData {
    final_data: PubInitConfidentialTxData,
    memo: ReverseConfidentialTxMemo,
    sig: Signature,
}

/// The interface for confidential transaction.
pub trait ConfidentialTransactionSender {
    /// This is called by the sender of a confidential transaction. The outputs
    /// can be safely placed on the chain. It corresponds to `CreateCTX` function of
    /// MERCAT paper.
    fn create(
        &self,
        sndr_enc_keys: EncryptionKeys,
        sndr_sign_key: SignatureSecKey,
        sndr_account: PubAccount,
        rcvr_pub_key: EncryptionPubKey,
        rcvr_account: PubAccount,
        asset_id: u32,
        amount: u32,
        rng: &mut StdRng,
    ) -> Fallible<(PubInitConfidentialTxData, ConfidentialTxState)>;
}

pub trait ConfidentialTransactionInitVerifier {
    fn verify(
        &self,
        transaction: PubInitConfidentialTxData,
        sndr_sign_pub_key: SignaturePubKey,
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
        rcvr_sign_key: SignatureSecKey,
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

pub trait ConfidentialTransactionReverseAndProcessMediator {
    /// This function is called by the mediator to reverse and process the reversal of
    /// the transaction. It corresponds to `ReverseCTX` of the MERCAT paper.
    fn create(
        &self,
        conf_tx_final_data: PubFinalConfidentialTxData,
        mdtr_enc_keys: EncryptionSecKey,
        mdtr_sign_key: SignatureSecKey,
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
