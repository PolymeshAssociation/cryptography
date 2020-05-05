//! mercat is the library that implements the confidential transactions
//! of the MERCAT, as defined in the section 6 of the whitepaper.

use crate::asset_proofs::correctness_proof::{CorrectnessFinalResponse, CorrectnessInitialMessage};
use crate::asset_proofs::encrypting_same_value_proof::{
    EncryptingSameValueFinalResponse, EncryptingSameValueInitialMessage,
};
use crate::asset_proofs::wellformedness_proof::{
    WellformednessFinalResponse, WellformednessInitialMessage,
};
use crate::asset_proofs::{CipherText, ElgamalPublicKey, ElgamalSecretKey};
use bulletproofs::RangeProof;
use curve25519_dalek::ristretto::CompressedRistretto;
use failure::Error;

// ---------------------- START: temporary types, move them to the proper location

// TODO move after CRYP-60 is done
type PubAddress = ElgamalPublicKey;
type SecAddress = ElgamalSecretKey;

// TODO move after CRYP-40
pub struct MembershipProofInitialMessage {}
pub struct MembershipProofFinalResponse {}

// TODO move after CRYP-71
pub struct Signature {}

// ---------------------- END: temporary types, move them to other files

// ---------------- type aliases for better code readability

/// Type alias for Twisted Elgamal ciphertext of asset ids.
pub type EncryptedAssetID = CipherText;

/// Type alias for Twisted Elgamal ciphertext of account amounts/balances.
pub type EncryptedAmount = CipherText;

/// Type alias for the tuple of initial message and final response of a non-interactive ZKP for wellformedness.
pub type WellformednessProof = (WellformednessInitialMessage, WellformednessFinalResponse);

/// Type alias for the tuple of initial message and final response of a non-interactive ZKP for correctness.
pub type CorrectnessProof = (CorrectnessInitialMessage, CorrectnessFinalResponse);

/// Type alias for the tuple of initial message and final response of a non-interactive ZKP for membership.
pub type MembershipProof = (MembershipProofInitialMessage, MembershipProofFinalResponse);

/// Type alias for the tuple of initial message and final response of a non-interactive ZKP for range.
pub type InRangeProof = (RangeProof, CompressedRistretto, usize);

/// Type alias for the tuple of initial message and final response of a non-interactive ZKP for cipher
/// equality under different public key.
pub type CipherEqualityProof = (
    EncryptingSameValueInitialMessage,
    EncryptingSameValueFinalResponse,
);

/// Asset memo. TODO: more informative description!
pub type AssetMemo = EncryptedAmount;

// ------------------ account

/// Holds the account memo. TODO: more informative description!
pub struct AccountMemo {
    y: ElgamalPublicKey,
    timestamp: std::time::Instant,
}

/// Holds the public portion of an account which can be safely put on the chain.
pub struct PubAccount {
    enc_asset_id: EncryptedAssetID,
    enc_balance: EncryptedAmount,
    asset_wellformedness_proof: WellformednessProof,
    asset_membership_proof: MembershipProof,
    balance_correctness_proof: CorrectnessProof,
    memo: AccountMemo,
    sign: Signature,
}

// TODO Account creation is part of CRYP-61

// ----------------- States

/// Represents the three substates (started, verified, rejected) of a
/// confidential transaction state.
#[derive(Debug)]
pub enum TXSubstate {
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
pub enum AssetTXState {
    Initialization(TXSubstate),
    Justification(TXSubstate),
}

/// Represents the four states (initialized, justified, finalized, reversed) of a
/// confidentional transaction.
#[derive(Debug)]
pub enum ConfidentialTXState {
    Initialization(TXSubstate),
    InitilaziationJustification(TXSubstate),
    Finalization(TXSubstate),
    Reversal(TXSubstate),
}

// ----------------------------- Asset Issuance

/// Holds the public portion of an asset issuance transaction. This can be placed
/// on the chain.
pub struct PubAssetTXData {
    enc_asset_id: EncryptedAssetID,
    enc_amount: EncryptedAmount,
    memo: AssetMemo,
    asset_id_equal_cipher_proof: CipherEqualityProof,
    balance_wellformedness_proof: WellformednessProof,
    balance_correctness_proof: CorrectnessProof,
    sig: Signature,
}

/// The interface for the confidential asset issuance.
pub trait AssetTXer {
    /// Initializes a confidentional asset issue transaction. Note that the returing
    /// values of this function contain sensetive information. Corresponds
    /// to `CreateAssetIssuanceTx` MERCAT whitepaper.
    fn initialize(
        &self,
        issr_addr: (PubAddress, SecAddress),
        amount: u32,
        issr_account: PubAccount,
        mdtr_pub_key: ElgamalPublicKey,
        asset_id: u32, // deviation from the paper
    ) -> Result<(PubAssetTXData, AssetTXState), Error>;

    /// Called by validators to verify the ZKP of the wellformedness of encrypted balance
    /// and to verify the signature.
    fn verify_initialization(
        &self,
        asset_tx: PubAssetTXData,
        state: AssetTXState,
    ) -> Result<AssetTXState, Error>;

    /// Justifies and processes a confidential asset issue transaction. This method is called
    /// by mediator. Corresponds to `JustifyAssetTx` and `ProcessCTX` of MERCAT paper.
    /// If the trasaction is justified, it will be processed immediately.
    fn justify_and_process(
        &self,
        asset_tx: PubAssetTXData,
        issr_account: PubAccount,
        state: AssetTXState,
        mdtr_addr: (PubAddress, SecAddress),
        issr_pub_key: ElgamalPublicKey,
        issr_acount: PubAccount,
    ) -> Result<(Signature, PubAccount, AssetTXState), Error>;

    /// Called by validators to verify the justification and processing of the transaction.
    fn verify_justification_and_process(
        &self,
        sig: Signature,
        issr_account: PubAccount,
    ) -> Result<AssetTXState, Error>;
}

// ----------------------------- Confidential Transaction

/// Holds the memo for confidential transaction sent by the sender.
pub struct ConfidentialTXMemo {
    enc_amount_using_sndr: EncryptedAmount,
    enc_amount_using_rcvr: EncryptedAmount,
    sndr_pub_key: ElgamalPublicKey,
    rcvr_pub_key: ElgamalPublicKey,
    enc_refreshed_amount: EncryptedAmount,
    asset_id_enc_using_rcvr: EncryptedAssetID,
}

/// Holds the memo for reversal of the confidential transaction sent by the mediator.
pub struct ReverseConfidentialTXMemo {
    enc_amount_using_rcvr: EncryptedAmount,
    enc_refreshed_amount: EncryptedAmount,
    asset_id_enc_using_rcvr: EncryptedAssetID,
}

/// Holds the public portion of the confidential transaction sent by the sender.
pub struct PubInitConfidentialTXData {
    amount_equal_cipher_proof: CipherEqualityProof,
    non_neg_amount_proof: InRangeProof,
    enough_fund_proof: InRangeProof,
    memo: ConfidentialTXMemo,
    asset_id_equal_cipher_proof: CipherEqualityProof,
    sig: Signature,
}

/// Holds the public portion of the confidential transaction that is finalized by
/// receiver.
pub struct PubFinalConfidentialTXData {
    init_data: PubInitConfidentialTXData,
    asset_id_equal_cipher_proof: CipherEqualityProof,
    amount_equal_cipher_proof: CipherEqualityProof, // deviation from the paper
    sig: Signature,
}

/// Holds the public portion of the reversal transaction.
pub struct PubReverseConfidentialTXData {
    final_data: PubInitConfidentialTXData,
    memo: ReverseConfidentialTXMemo,
    sig: Signature,
}

/// The interface for confidential transaction.
pub trait ConfidentialTXer {
    /// This is called by the sender of a confidential transaction. The outputs
    /// can be safely placed on the chain. It corresponds to `CreateCTX` function of
    /// MERCAT paper.
    fn create(
        &self,
        sndr_addr: (PubAddress, SecAddress),
        sndr_account: PubAccount,
        rcvr_pub_key: ElgamalPublicKey,
        rcvr_account: PubAccount,
        asset_id: u32,
        amount: u32,
    ) -> Result<(PubInitConfidentialTXData, ConfidentialTXState), Error>;

    fn verify_create(
        &self,
        transaction: PubInitConfidentialTXData,
    ) -> Result<ConfidentialTXState, Error>;

    /// Justify the transaction by mediator.
    /// TODO: missing from the paper, will discuss and decide later.
    fn justify_init() -> Result<ConfidentialTXState, Error>;

    /// This function is called the receiver of the transaction to finalize and process
    /// the transaction. It corresponds to `FinalizeCTX` and `ProcessCTX` functions
    /// of the MERCAT paper.
    fn finalize_and_process(
        &self,
        conf_tx_init_data: PubInitConfidentialTXData,
        rcvr_addr: (PubAddress, SecAddress),
        sndr_pub_key: ElgamalPublicKey,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        enc_asset_id: EncryptedAssetID,
        amount: u32,
        state: ConfidentialTXState,
    ) -> Result<(PubFinalConfidentialTXData, ConfidentialTXState), Error>;

    /// This is called by the validators to verify the finalized transaction.
    fn verify_finalize_and_process(
        &self,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        conf_tx_final_data: PubFinalConfidentialTXData,
        state: ConfidentialTXState,
    ) -> Result<ConfidentialTXState, Error>;

    /// This function is called by the mediator to reverse and process the reversal of
    /// the transaction. It corresponds to `ReverseCTX` of the MERCAT paper.
    fn reverse_and_process(
        &self,
        conf_tx_final_data: PubFinalConfidentialTXData,
        mdtr_addr: SecAddress,
        state: ConfidentialTXState,
    ) -> Result<(PubReverseConfidentialTXData, ConfidentialTXState), Error>;

    /// This function is called by validators to verify the reversal and processing of the
    /// reversal transaction.
    fn verify_reverse_and_process(
        &self,
        reverse_conf_tx_data: PubReverseConfidentialTXData,
        state: ConfidentialTXState,
    ) -> Result<ConfidentialTXState, Error>;
}
