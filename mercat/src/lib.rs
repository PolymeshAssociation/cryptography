//! mercat is the library that implements the confidential transactions
//! of the MERCAT, as defined in the section 6 of the whitepaper.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

use codec::{Decode, Encode};
use cryptography_core::{
    asset_proofs::{
        ciphertext_refreshment_proof::CipherEqualSamePubKeyProof,
        correctness_proof::CorrectnessProof,
        encrypting_same_value_proof::CipherEqualDifferentPubKeyProof,
        membership_proof::MembershipProof, range_proof::InRangeProof,
        wellformedness_proof::WellformednessProof, CipherText, CipherTextWithHint,
        CommitmentWitness, ElgamalPublicKey, ElgamalSecretKey,
    },
    errors::Fallible,
    AssetId, Balance,
};
pub use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sp_std::{fmt, vec::Vec};

/// That `ensure` does not transform into a string representation like `failure::ensure` is doing.
#[allow(unused_macros)]
macro_rules! ensure {
    ($predicate:expr, $context_selector:expr) => {
        if !$predicate {
            return Err($context_selector.into());
        }
    };
}

/// Helper macro to assert that `predicate` is an `Error::from( $err)`.
#[allow(unused_macros)]
macro_rules! assert_err {
    ($predicate:expr, $err:expr) => {
        assert_eq!($predicate.expect_err("Error expected").kind(), &$err);
    };
}

// -------------------------------------------------------------------------------------
// -                                  Constants                                        -
// -------------------------------------------------------------------------------------

const EXPONENT: u32 = 8;
const BASE: u32 = 4;

// -------------------------------------------------------------------------------------
// -                                 New Type Def                                      -
// -------------------------------------------------------------------------------------

/// Holds ElGamal encryption public key.
pub type EncryptionPubKey = ElgamalPublicKey;

/// Holds ElGamal encryption secret key.
pub type EncryptionSecKey = ElgamalSecretKey;

/// Holds ElGamal encryption keys.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EncryptionKeys {
    pub public: EncryptionPubKey,
    pub secret: EncryptionSecKey,
}

/// New type for Twisted ElGamal ciphertext of asset ids.
pub type EncryptedAssetId = CipherText;

/// New type for Twisted ElGamal ciphertext of account amounts/balances.
pub type EncryptedAmount = CipherText;

/// New type for ElGamal ciphertext of a transferred amount.
pub type EncryptedAmountWithHint = CipherTextWithHint;

// -------------------------------------------------------------------------------------
// -                                    Account                                        -
// -------------------------------------------------------------------------------------

#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MediatorAccount {
    pub encryption_key: EncryptionKeys,
}

#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PubAccount {
    // enc_asset_id acts as the account id.
    pub enc_asset_id: EncryptedAssetId,
    pub owner_enc_pub_key: EncryptionPubKey,
}

/// Holds contents of the public portion of an account which can be safely put on the chain.
#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PubAccountTx {
    pub pub_account: PubAccount,
    pub initial_balance: EncryptedAmount,
    pub asset_wellformedness_proof: WellformednessProof,
    pub asset_membership_proof: MembershipProof,
    pub initial_balance_correctness_proof: CorrectnessProof,
}

/// Holds the secret keys and asset id of an account. This cannot be put on the change.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecAccount {
    pub enc_keys: EncryptionKeys,
    pub asset_id_witness: CommitmentWitness,
}

/// Wrapper for both the secret and public account info
#[derive(Clone, Debug)]
pub struct Account {
    pub public: PubAccount,
    pub secret: SecAccount,
}

/// The interface for the account creation.
pub trait AccountCreatorInitializer {
    /// Creates a public account for a user and initializes the balance to zero.
    /// Corresponds to `CreateAccount` method of the MERCAT paper.
    /// This function assumes that the given input `account_id` is unique.
    fn create<T: RngCore + CryptoRng>(
        &self,
        secret: &SecAccount,
        valid_asset_ids: &[Scalar],
        rng: &mut T,
    ) -> Fallible<PubAccountTx>;
}

/// The interface for the verifying the account creation.
pub trait AccountCreatorVerifier {
    /// Called by the validators to ensure that the account was created correctly.
    fn verify(&self, account: &PubAccountTx, valid_asset_ids: &[Scalar]) -> Fallible<()>;
}

// -------------------------------------------------------------------------------------
// -                               Transaction State                                   -
// -------------------------------------------------------------------------------------

/// Represents the three substates (started, verified, rejected) of a
/// confidential transaction state.
#[derive(Copy, Clone, PartialEq, Eq, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TxSubstate {
    /// The action on transaction has been taken but is not verified yet.
    Started,
    /// The action on transaction has been verified by validators.
    Validated,
    /// The action on transaction has failed the verification by validators.
    Rejected,
}

impl fmt::Display for TxSubstate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match self {
            TxSubstate::Started => "started",
            TxSubstate::Validated => "validated",
            TxSubstate::Rejected => "rejected",
        };
        write!(f, "{}", str)
    }
}

/// Represents the two states (initialized, justified) of a
/// confidential asset issuance transaction.
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AssetTxState {
    Initialization(TxSubstate),
    Justification(TxSubstate),
}

impl fmt::Display for AssetTxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetTxState::Initialization(substate) => {
                write!(f, "asset-initialization-{}", substate)
            }
            AssetTxState::Justification(substate) => write!(f, "asset-justification-{}", substate),
        }
    }
}

impl core::fmt::Debug for AssetTxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetTxState::Initialization(substate) => {
                write!(f, "asset-initialization-{}", substate)
            }
            AssetTxState::Justification(substate) => write!(f, "asset-justification-{}", substate),
        }
    }
}

/// Represents the four states (initialized, justified, finalized, reversed) of a
/// confidential transaction.
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TransferTxState {
    Initialization(TxSubstate),
    Finalization(TxSubstate),
    Justification(TxSubstate),
    Reversal(TxSubstate),
}

impl fmt::Display for TransferTxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferTxState::Initialization(substate) => {
                write!(f, "transfer-initialization-{}", substate)
            }
            TransferTxState::Finalization(substate) => {
                write!(f, "transfer-finalization-{}", substate)
            }
            TransferTxState::Justification(substate) => {
                write!(f, "transfer-justification-{}", substate)
            }
            TransferTxState::Reversal(substate) => write!(f, "transfer-reversal-{}", substate),
        }
    }
}

impl core::fmt::Debug for TransferTxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferTxState::Initialization(substate) => write!(f, "initialization_{}", substate),
            TransferTxState::Finalization(substate) => write!(f, "finalization_{}", substate),
            TransferTxState::Justification(substate) => write!(f, "justification_{}", substate),
            TransferTxState::Reversal(substate) => write!(f, "reversal_{}", substate),
        }
    }
}

// -------------------------------------------------------------------------------------
// -                                 Asset Issuance                                    -
// -------------------------------------------------------------------------------------

/// Asset memo holds the contents of an asset issuance transaction.
#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AssetMemo {
    pub enc_issued_amount: EncryptedAmount,
}

/// Holds the public portion of an asset issuance transaction after initialization.
/// This can be placed on the chain.
#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InitializedAssetTx {
    pub account_id: EncryptedAssetId,
    pub memo: AssetMemo,
    pub balance_wellformedness_proof: WellformednessProof,
    pub balance_correctness_proof: CorrectnessProof,
    pub auditors_payload: Vec<AuditorPayload>,
}

/// The interface for the confidential asset issuance transaction.
pub trait AssetTransactionIssuer {
    /// Initializes a confidential asset issue transaction. Note that the returning
    /// values of this function contain sensitive information. Corresponds
    /// to `CreateAssetIssuanceTx` MERCAT whitepaper.
    fn initialize_asset_transaction<T: RngCore + CryptoRng>(
        &self,
        issr_account: &Account,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<InitializedAssetTx>;
}

pub trait AssetTransactionVerifier {
    /// Called by validators to verify the justification and processing of the transaction.
    fn verify_asset_transaction(
        &self,
        amount: u32,
        justified_asset_tx: &InitializedAssetTx,
        issr_account: &PubAccount,
        issr_init_balance: &EncryptedAmount,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
    ) -> Fallible<EncryptedAmount>;
}

pub trait AssetTransactionAuditor {
    /// Verify the initialized, and justified transactions.
    /// Audit the sender's encrypted amount.
    fn audit_asset_transaction(
        &self,
        justified_asset_tx: &InitializedAssetTx,
        issuer_account: &PubAccount,
        auditor_enc_keys: &(u32, EncryptionKeys),
    ) -> Fallible<()>;
}

// -------------------------------------------------------------------------------------
// -                       Confidential Transfer Transaction                           -
// -------------------------------------------------------------------------------------

#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuditorPayload {
    pub auditor_id: u32,
    pub encrypted_amount: EncryptedAmountWithHint,
    pub amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
}

/// Holds the memo for confidential transaction sent by the sender.
#[derive(Default, Clone, Copy, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TransferTxMemo {
    pub sender_account_id: EncryptedAssetId,
    pub receiver_account_id: EncryptedAssetId,
    pub enc_amount_using_sender: EncryptedAmount,
    pub enc_amount_using_receiver: EncryptedAmount,
    pub refreshed_enc_balance: EncryptedAmount,
    pub refreshed_enc_asset_id: EncryptedAssetId,
    pub enc_asset_id_using_receiver: EncryptedAssetId,
    pub enc_asset_id_for_mediator: EncryptedAssetId,
    pub enc_amount_for_mediator: EncryptedAmountWithHint,
}

/// Holds the proofs and memo of the confidential transaction sent by the sender.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InitializedTransferTx {
    pub amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
    pub non_neg_amount_proof: InRangeProof,
    pub enough_fund_proof: InRangeProof,
    pub memo: TransferTxMemo,
    pub asset_id_equal_cipher_with_sender_receiver_keys_proof: CipherEqualDifferentPubKeyProof,
    pub balance_refreshed_same_proof: CipherEqualSamePubKeyProof,
    pub asset_id_refreshed_same_proof: CipherEqualSamePubKeyProof,
    pub asset_id_correctness_proof: CorrectnessProof,
    pub amount_correctness_proof: CorrectnessProof,
    pub auditors_payload: Vec<AuditorPayload>,
}

/// Holds the initial transaction data and the proof of equality of asset ids
/// prepared by the receiver.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FinalizedTransferTx {
    pub init_data: InitializedTransferTx,
    pub asset_id_from_sender_equal_to_receiver_proof: CipherEqualSamePubKeyProof,
}

/// Wrapper for the contents and auditors' payload.
#[derive(Clone, Encode, Decode, Debug)]
pub struct JustifiedTransferTx {
    pub finalized_data: FinalizedTransferTx,
}

/// The interface for confidential transaction.
pub trait TransferTransactionSender {
    /// This is called by the sender of a confidential transaction. The outputs
    /// can be safely placed on the chain. It corresponds to `CreateCTX` function of
    /// MERCAT paper.
    fn create_transaction<T: RngCore + CryptoRng>(
        &self,
        sender_account: &Account,
        sender_init_balance: &EncryptedAmount,
        receiver_pub_account: &PubAccount,
        mediator_pub_key: &EncryptionPubKey,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<InitializedTransferTx>;
}

pub trait TransferTransactionReceiver {
    /// This function is called the receiver of the transaction to finalize and process
    /// the transaction. It corresponds to `FinalizeCTX` and `ProcessCTX` functions
    /// of the MERCAT paper.
    fn finalize_transaction<T: RngCore + CryptoRng>(
        &self,
        initialized_transaction: InitializedTransferTx,
        receiver_account: Account,
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<FinalizedTransferTx>;
}

pub trait TransferTransactionMediator {
    /// Justify the transaction by mediator.
    fn justify_transaction<R: RngCore + CryptoRng>(
        &self,
        finalized_transaction: FinalizedTransferTx,
        mediator_enc_keys: &EncryptionKeys,
        sender_account: &PubAccount,
        sender_init_balance: &EncryptedAmount,
        receiver_account: &PubAccount,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
        asset_id_hint: AssetId,
        rng: &mut R,
    ) -> Fallible<JustifiedTransferTx>;
}

pub trait TransferTransactionVerifier {
    /// Verify the initialized, finalized, and justified transactions.
    fn verify_transaction<R: RngCore + CryptoRng>(
        &self,
        justified_transaction: &JustifiedTransferTx,
        sender_account: &PubAccount,
        sender_init_balance: &EncryptedAmount,
        receiver_account: &PubAccount,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
        rng: &mut R,
    ) -> Fallible<()>;
}

pub trait TransferTransactionAuditor {
    /// Verify the initialized, finalized, and justified transactions.
    /// Audit the sender's encrypted amount.
    fn audit_transaction(
        &self,
        justified_transaction: &JustifiedTransferTx,
        sender_account: &PubAccount,
        receiver_account: &PubAccount,
        auditor_enc_keys: &(u32, EncryptionKeys),
    ) -> Fallible<()>;
}

// -------------------------------------------------------------------------------------
// -                         Reversal Confidential Transaction                         -
// -------------------------------------------------------------------------------------

/// Holds the public portion of the reversal transaction.
pub struct ReversedTransferTx {
    _final_data: InitializedTransferTx,
    _memo: ReversedTransferTxMemo,
}

/// Holds the memo for reversal of the confidential transaction sent by the mediator.
pub struct ReversedTransferTxMemo {
    _enc_amount_using_receiver: EncryptedAmount,
    _enc_refreshed_amount: EncryptedAmount,
    _enc_asset_id_using_receiver: EncryptedAssetId,
}

pub trait ReversedTransferTransactionMediator {
    /// This function is called by the mediator to reverse and process the reversal of
    /// the transaction. It corresponds to `ReverseCTX` of the MERCAT paper.
    fn create(
        &self,
        transaction_final_data: FinalizedTransferTx,
        mediator_enc_keys: EncryptionSecKey,
        state: TransferTxState,
    ) -> Fallible<(ReversedTransferTx, TransferTxState)>;
}

pub trait ReversedTransferTransactionVerifier {
    /// This function is called by validators to verify the reversal and processing of the
    /// reversal transaction.
    fn verify(
        &self,
        reverse_transaction_data: ReversedTransferTx,
        state: TransferTxState,
    ) -> Fallible<TransferTxState>;
}

pub mod account;
pub mod asset;
pub mod transaction;
