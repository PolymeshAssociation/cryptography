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

// ----------------- State

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
        self,
        issr_addr: Address,
        amount: u32,
        issr_account: PubAccount,
        mdtr_pub_key: ElgamalPublicKey,
        asset_id: u32, // deviation from the paper
    ) -> Result<(AssetTXData, AssetTXState), Error>;

    /// Justifies a confidential asset issue transaction. This method is called
    /// by mediator. Corresponds to `JustifyAssetTx` of MERCAT paper.
    fn justify(
        self,
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
    fn process(self, memo: AssetMemo, issr_account: PubAccount) -> Result<PubAccount, Error>;
}
