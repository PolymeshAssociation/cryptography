//! mercat is the library that implements the confidential transactions
//! of the MERCAT, as defined in the section 6 of the whitepaper.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

use codec::{Decode, Encode};
pub use confidential_identity_core;
use confidential_identity_core::asset_proofs::{
    ciphertext_refreshment_proof::CipherEqualSamePubKeyProof,
    correctness_proof::CorrectnessProof,
    encrypting_same_value_proof::CipherEqualDifferentPubKeyProof,
    errors::{ErrorKind, Fallible},
    range_proof::InRangeProof,
    wellformedness_proof::WellformednessProof,
    Balance, CipherText, CipherTextWithHint, ElgamalPublicKey, ElgamalSecretKey,
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
    pub owner_enc_pub_key: EncryptionPubKey,
}

/// Holds contents of the public portion of an account which can be safely put on the chain.
#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PubAccountTx {
    pub pub_account: PubAccount,
    pub initial_balance: EncryptedAmount,
    pub initial_balance_correctness_proof: CorrectnessProof,
}

/// Holds the secret keys and asset id of an account. This cannot be put on the change.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecAccount {
    pub enc_keys: EncryptionKeys,
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
        rng: &mut T,
    ) -> Fallible<PubAccountTx>;
}

/// The interface for the verifying the account creation.
pub trait AccountCreatorVerifier {
    /// Called by the validators to ensure that the account was created correctly.
    fn verify(&self, account: &PubAccountTx) -> Fallible<()>;
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
    pub account: PubAccount,
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
        auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<InitializedAssetTx>;
}

pub trait AssetTransactionVerifier {
    /// Called by validators to verify the justification and processing of the transaction.
    fn verify_asset_transaction(
        &self,
        amount: Balance,
        justified_asset_tx: &InitializedAssetTx,
        issr_account: &PubAccount,
        issr_init_balance: &EncryptedAmount,
        auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
    ) -> Fallible<EncryptedAmount>;
}

pub trait AssetTransactionAuditor {
    /// Verify the initialized, and justified transactions.
    /// Audit the sender's encrypted amount.
    fn audit_asset_transaction(
        &self,
        justified_asset_tx: &InitializedAssetTx,
        issuer_account: &PubAccount,
        auditor_enc_keys: &(AuditorId, EncryptionKeys),
    ) -> Fallible<()>;
}

// -------------------------------------------------------------------------------------
// -                       Confidential Transfer Transaction                           -
// -------------------------------------------------------------------------------------

pub type AuditorId = u32;

#[derive(Clone, Debug)]
pub enum AmountSource<'a> {
    Encrypted(&'a EncryptionKeys),
    Amount(Balance),
}

impl AmountSource<'_> {
    pub fn get_amount(&self, enc_amount: Option<&EncryptedAmountWithHint>) -> Fallible<Balance> {
        match (self, enc_amount) {
            (Self::Amount(amount), _) => Ok(*amount),
            (Self::Encrypted(keys), Some(enc_amount)) => {
                Ok(keys.secret.const_time_decrypt(enc_amount)?)
            }
            _ => Err(ErrorKind::CipherTextDecryptionError.into()),
        }
    }
}

#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuditorPayload {
    pub auditor_id: AuditorId,
    pub encrypted_amount: EncryptedAmountWithHint,
    pub amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
}

/// Holds the memo for confidential transaction sent by the sender.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TransferTxMemo {
    pub sender_account: PubAccount,
    pub receiver_account: PubAccount,
    pub enc_amount_using_sender: EncryptedAmount,
    pub enc_amount_using_receiver: EncryptedAmount,
    pub refreshed_enc_balance: EncryptedAmount,
    pub enc_amount_for_mediator: Option<EncryptedAmountWithHint>,
}

/// Holds the proofs and memo of the confidential transaction sent by the sender.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InitializedTransferTx {
    pub amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
    pub non_neg_amount_proof: InRangeProof,
    pub enough_fund_proof: InRangeProof,
    pub memo: TransferTxMemo,
    pub balance_refreshed_same_proof: CipherEqualSamePubKeyProof,
    pub amount_correctness_proof: CorrectnessProof,
    pub auditors_payload: Vec<AuditorPayload>,
}

/// TODO: remove, not needed.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FinalizedTransferTx {}

/// Wrapper for the contents and auditors' payload.
#[derive(Clone, Encode, Decode, Debug)]
pub struct JustifiedTransferTx {}

/// The interface for confidential transaction.
pub trait TransferTransactionSender {
    /// This is called by the sender of a confidential transaction. The outputs
    /// can be safely placed on the chain. It corresponds to `CreateCTX` function of
    /// MERCAT paper.
    fn create_transaction<T: RngCore + CryptoRng>(
        &self,
        sender_account: &Account,
        sender_init_balance: &EncryptedAmount,
        sender_balance: Balance,
        receiver_pub_account: &PubAccount,
        mediator_pub_key: Option<&EncryptionPubKey>,
        auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<InitializedTransferTx>;
}

pub trait TransferTransactionReceiver {
    /// This function is called the receiver of the transaction to finalize and process
    /// the transaction. It corresponds to `FinalizeCTX` and `ProcessCTX` functions
    /// of the MERCAT paper.
    fn finalize_transaction(
        &self,
        initialized_transaction: &InitializedTransferTx,
        receiver_account: Account,
        amount: Balance,
    ) -> Fallible<FinalizedTransferTx>;
}

pub trait TransferTransactionMediator {
    /// Justify the transaction by mediator.
    fn justify_transaction<R: RngCore + CryptoRng>(
        &self,
        init_tx: &InitializedTransferTx,
        finalized_tx: &FinalizedTransferTx,
        amount_source: AmountSource,
        sender_account: &PubAccount,
        sender_init_balance: &EncryptedAmount,
        receiver_account: &PubAccount,
        auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
        rng: &mut R,
    ) -> Fallible<JustifiedTransferTx>;
}

pub trait TransferTransactionVerifier {
    /// Verify the initialized, finalized, and justified transactions.
    fn verify_transaction<R: RngCore + CryptoRng>(
        &self,
        init_tx: &InitializedTransferTx,
        finalized_tx: &FinalizedTransferTx,
        sender_account: &PubAccount,
        sender_init_balance: &EncryptedAmount,
        receiver_account: &PubAccount,
        auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
        rng: &mut R,
    ) -> Fallible<()>;
}

pub trait TransferTransactionAuditor {
    /// Verify the initialized, finalized, and justified transactions.
    /// Audit the sender's encrypted amount.
    fn audit_transaction(
        &self,
        init_tx: &InitializedTransferTx,
        finalized_tx: &FinalizedTransferTx,
        sender_account: &PubAccount,
        receiver_account: &PubAccount,
        auditor_enc_keys: &(AuditorId, EncryptionKeys),
    ) -> Fallible<()>;
}

pub mod account;
pub mod asset;
pub mod transaction;
