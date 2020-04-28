//! mercat is the library that implements the confidential transactions
//! of the MERCAT, as defined in the section 6 of the whitepaper.

use crate::asset_proofs::correctness_proof::{CorrectnessFinalResponse, CorrectnessInitialMessage};
use crate::asset_proofs::wellformedness_proof::{
    WellformednessFinalResponse, WellformednessInitialMessage,
};
use crate::asset_proofs::{CipherText, ElgamalPublicKey, ElgamalSecretKey};
use failure::{Error, Fail};

// ---------------------- START: temporary types, move them to the proper location

// TODO move after CRYP-60 is done
type PubAddress = ElgamalPublicKey;
type SecAddress = ElgamalSecretKey;
pub struct Address {
    pk: PubAddress,
    sk: SecAddress,
}

// TODO move after CRYP-40
pub struct MembershipProofInitialMessage {}
pub struct MembershipProofFinalResponse {}

// TODO move after CRYP-40
pub struct RangeProofInitialMessage {}
pub struct RangeProofFinalResponse {}

// TODO move after CRYP-26
pub struct CipherEqualityProofInitialMessage {}
pub struct CipherEqualityProofFinalResponse {}

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
pub type RangeProof = (RangeProofInitialMessage, RangeProofFinalResponse);

/// Type alias for the tuple of initial message and final response of a non-interactive ZKP for cipher
/// equality under different public key.
pub type CipherEqualityProof = (
    CipherEqualityProofInitialMessage,
    CipherEqualityProofFinalResponse,
);

// Asset memo. TODO: more informative description!
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
    memo: AccountMemo,
    sign: Signature,
}

/// Holds the private portion of an account. This should be protected and
/// communicated between parties through secure channels.
pub struct SecAccount {
    balance_correctness_proof: CorrectnessProof,
    memo: AccountMemo, // new: deviation from the paper
    sign: Signature,   // new: deviation from the paper
}

/// Is an auxilary type to hold both public and private portions of an account.
pub struct Account {
    pblc: PubAccount,
    scrt: SecAccount,
}

// TODO Account creation is part of CRYP-61

// ----------------- States

/// Represents the three substates (started, verified, rejected) of a
/// on a confidential transaction state.
#[derive(Debug)]
pub enum TXSubstate {
    /// The action on transaction has been taken but is not verified yet.
    Started,
    /// The action on transaction has been verified by validators.
    Verified,
    /// The action on transaction has failed the verification by validators.
    Rejected,
}

/// Represents the three states (initialized, justified, finalized) of a
/// confidentional asset issuance transaction.
#[derive(Debug)]
pub enum AssetTXState {
    Initialization(TXSubstate),
    InitilaziationJustification(TXSubstate),
    Finalization(TXSubstate),
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
    sig: Signature,
}

/// Holds the secret portion of an asset issuance transaction. This should be
/// communicated between the issuer and the mediator over a secure channels.
pub struct SecAssetTXData {
    balance_correctness_proof: CorrectnessProof,
    sig: Signature, // new: deviation from the paper
}

/// An auxilary type to reflect both the public and private portions of an
/// asset issuance transaction data.
/// NOTE: these auxilary types can be removed in favour of more explicit naming
pub struct AssetTXData {
    pblc: PubAssetTXData,
    scrt: SecAssetTXData,
}

/// The interface for the confidential asset issuance.
pub trait AssetTXer {
    /// Initializes a confidentional asset issue transaction. Note that the returing
    /// values of this function contain sensetive information. Corresponds
    /// to `CreateAssetIssuanceTx` MERCAT whitepaper.
    fn initialize(
        &self,
        issr_addr: Address,
        amount: u32,
        issr_account: PubAccount,
        mdtr_pub_key: ElgamalPublicKey,
        asset_id: u32, // deviation from the paper
    ) -> Result<(AssetTXData, AssetTXState), Error>;
    // NOTE: a good convension can be to let all the functions have the following
    //       format: Result<(public_data, private_data, state), error>
    //       what do you think?
    //) -> Result<(PubAssetTXData, SecAssetTXData, AssetTXState), Error>;

    /// Justifies a confidential asset issue transaction. This method is called
    /// by mediator. Corresponds to `JustifyAssetTx` of MERCAT paper.
    fn justify(
        &self,
        asset_tx: AssetTXData,
        issr_acc: PubAccount,
        state: AssetTXState,
        mdtr_addr: Address,
        issr_pub_key: ElgamalPublicKey,
        issr_acount: PubAccount,
        amount: u32, // deviation from the paper
    ) -> Result<(AssetTXState, Signature), Error>;

    /// Processes a confidential asset issue transaction. This method is called
    /// by "system algorithms". Corresponds to part 4 of `ProcessCTX` of MERCAT paper.
    fn process(
        &self,
        memo: AssetMemo,
        issr_account: PubAccount,
        state: AssetTXState,
    ) -> Result<PubAccount, Error>;

    /// verification that is done by validators on the chain
    /// TODO: missing from the paper. Probably need to verify functions,
    /// one for initialize and one for justify.
    fn verify();
}

// ----------------------------- Confidential Transaction

pub struct ConfidentialTXMemo {
    enc_amount_using_sndr: EncryptedAmount,
    enc_amount_using_rcvr: EncryptedAmount,
    sndr_pub_key: ElgamalPublicKey,
    rcvr_pub_key: ElgamalPublicKey,
    enc_refreshed_amount: EncryptedAmount,
    asset_id_enc_using_rcvr: EncryptedAssetID,
}

pub struct PubInitConfidentialTXData {
    amount_equal_cipher_proof: CipherEqualityProof,
    non_neg_amount_proof: RangeProof,
    enough_fund_proof: RangeProof,
    memo: ConfidentialTXMemo,
    asset_id_equal_cipher_proof: CipherEqualityProof,
    sig: Signature,
}

pub struct PubFinalConfidentialTXData {
    init_data: PubInitConfidentialTXData,
    asset_id_equal_cipher_proof: CipherEqualityProof,
    amount_equal_cipher_proof: CipherEqualityProof, // deviation from the paper
    sig: Signature,
}

pub trait ConfidentialTXer {
    /// This is called by the sender of a confidential transaction. The outputs
    /// can be safely placed on the chain. It corresponds to `CreateCTX` function of
    /// MERCAT paper.
    fn create(
        &self,
        sndr_addr: Address,
        sndr_account: PubAccount,
        rcvr_pub_key: ElgamalPublicKey,
        rcvr_account: PubAccount,
        asset_id: u32,
        amount: u32,
    ) -> Result<(PubInitConfidentialTXData, ConfidentialTXState), Error>;

    /// Justify the transaction by mediator.
    /// TODO: missing from the paper.
    fn justify_init() -> Result<ConfidentialTXState, Error>;

    /// This function is called the receiver of the transaction
    fn finalize_by_receiver(
        &self,
        conf_tx_init_data: PubInitConfidentialTXData,
        rcvr_addr: Address,
        sndr_pub_key: ElgamalPublicKey,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        enc_asset_id: EncryptedAssetID,
        amount: u32,
        state: ConfidentialTXState,
    ) -> Result<(PubFinalConfidentialTXData, ConfidentialTXState), Error>;

    /// This is called by the validators to verify the finalized transaction.
    /// TODO: I think we also need verify functions for create and justify_init.
    fn verify(
        &self,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        conf_tx_final_data: PubFinalConfidentialTXData,
    ) -> Result<ConfidentialTXState, Error>;

    /// This is called by the system algorithms to update the accounts of
    /// the sender and receiver once all the above steps have passed.
    fn process(
        &self,
        conf_tx_final_data: PubFinalConfidentialTXData,
        state: ConfidentialTXState,
    ) -> Result<(PubAccount, PubAccount, ConfidentialTXState), Error>;
}
