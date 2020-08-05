//! mercat is the library that implements the confidential transactions
//! of the MERCAT, as defined in the section 6 of the whitepaper.

pub mod account;
pub mod asset;
pub mod transaction;

use crate::{
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

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use schnorrkel::keys::{Keypair, PublicKey};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use codec::{Decode, Encode, Error as CodecError, Input, Output};
use sp_std::{convert::From, fmt, vec::Vec};

// -------------------------------------------------------------------------------------
// -                                  Constants                                        -
// -------------------------------------------------------------------------------------

const EXPONENT: u32 = 8;
const BASE: u32 = 4;

// -------------------------------------------------------------------------------------
// -                                 New Type Def                                      -
// -------------------------------------------------------------------------------------

// Having separate types for encryption and signature will ensure that the keys used for encryption
// and signing are different.

/// Holds ElGamal encryption public key.
pub type EncryptionPubKey = ElgamalPublicKey;

/// Holds ElGamal encryption secret key.
pub type EncryptionSecKey = ElgamalSecretKey;

/// Holds ElGamal encryption keys.
#[derive(Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct EncryptionKeys {
    pub pblc: EncryptionPubKey,
    pub scrt: EncryptionSecKey,
}

/// Holds the SR25519 signature scheme public key.
pub type SigningPubKey = PublicKey;
pub type SigningKeys = Keypair;
pub type Signature = schnorrkel::sign::Signature;

/// New type for Twisted ElGamal ciphertext of asset ids.
pub type EncryptedAssetId = CipherText;

/// New type for Twisted ElGamal ciphertext of account amounts/balances.
pub type EncryptedAmount = CipherTextWithHint;

/// Asset memo holds the contents of an asset issuance transaction.
#[derive(Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct AssetMemo {
    pub enc_issued_amount: EncryptedAmount,
    pub tx_id: u32,
}

// -------------------------------------------------------------------------------------
// -                                    Account                                        -
// -------------------------------------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct MediatorAccount {
    pub encryption_key: EncryptionKeys,
    pub signing_key: SigningKeys,
}

impl Encode for MediatorAccount {
    #[inline]
    fn size_hint(&self) -> usize {
        self.encryption_key.size_hint() + schnorrkel::KEYPAIR_LENGTH // signing_key
    }

    #[inline]
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.encryption_key.encode_to(dest);
        self.signing_key.to_bytes().encode_to(dest);
    }
}

impl Decode for MediatorAccount {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let encryption_key = <EncryptionKeys>::decode(input)?;

        let signing_key = <[u8; schnorrkel::KEYPAIR_LENGTH]>::decode(input)?;
        let signing_key = SigningKeys::from_bytes(&signing_key)
            .map_err(|_| CodecError::from("MediatorAccount.signing_key is invalid"))?;

        Ok(MediatorAccount {
            encryption_key,
            signing_key,
        })
    }
}

/// Holds the owner public keys and the creation date of an account.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct AccountMemo {
    pub owner_enc_pub_key: EncryptionPubKey,
    pub owner_sign_pub_key: SigningPubKey,
}

impl AccountMemo {
    pub fn new(owner_enc_pub_key: EncryptionPubKey, owner_sign_pub_key: SigningPubKey) -> Self {
        AccountMemo {
            owner_enc_pub_key,
            owner_sign_pub_key,
        }
    }
}

impl Encode for AccountMemo {
    #[inline]
    fn size_hint(&self) -> usize {
        self.owner_enc_pub_key.size_hint() + schnorrkel::PUBLIC_KEY_LENGTH // owner_sign_pub_key
    }

    #[inline]
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.owner_enc_pub_key.encode_to(dest);
        self.owner_sign_pub_key.to_bytes().encode_to(dest);
    }
}

impl Decode for AccountMemo {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let owner_enc_pub_key = <EncryptionPubKey>::decode(input)?;

        let owner_sign_pub_key = <[u8; schnorrkel::PUBLIC_KEY_LENGTH]>::decode(input)?;
        let owner_sign_pub_key = SigningPubKey::from_bytes(&owner_sign_pub_key)
            .map_err(|_| CodecError::from("AccountMemo.owner_sign_pub_key is invalid"))?;

        Ok(AccountMemo {
            owner_enc_pub_key,
            owner_sign_pub_key,
        })
    }
}

#[derive(Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct PubAccount {
    pub id: u32,
    pub enc_asset_id: EncryptedAssetId,
    pub enc_balance: EncryptedAmount,
    pub memo: AccountMemo,
}

/// Holds contents of the public portion of an account which can be safely put on the chain.
#[derive(Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct PubAccountContent {
    pub pub_account: PubAccount,
    pub asset_wellformedness_proof: WellformednessProof,
    pub asset_membership_proof: MembershipProof,
    pub initial_balance_correctness_proof: CorrectnessProof,
    pub tx_id: u32,
}

/// Wrapper for the account content and signature.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct PubAccountTx {
    pub content: PubAccountContent,
    pub sig: Signature,
}

impl Encode for PubAccountTx {
    #[inline]
    fn size_hint(&self) -> usize {
        self.content.size_hint() + schnorrkel::SIGNATURE_LENGTH // sig
    }

    #[inline]
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.content.encode_to(dest);
        self.sig.to_bytes().encode_to(dest);
    }
}

impl Decode for PubAccountTx {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let content = PubAccountContent::decode(input)?;
        let sig = <[u8; schnorrkel::SIGNATURE_LENGTH]>::decode(input)?;
        let sig = Signature::from_bytes(&sig)
            .map_err(|_| CodecError::from("PubAccount.sig is invalid"))?;

        Ok(PubAccountTx { content, sig })
    }
}

/// Holds the secret keys and asset id of an account. This cannot be put on the change.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct SecAccount {
    pub enc_keys: EncryptionKeys,
    pub sign_keys: SigningKeys,
    pub asset_id_witness: CommitmentWitness,
}

impl Encode for SecAccount {
    #[inline]
    fn size_hint(&self) -> usize {
        self.enc_keys.size_hint()
            + schnorrkel::KEYPAIR_LENGTH  // sign_keys
            + self.asset_id_witness.size_hint()
    }

    #[inline]
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.enc_keys.encode_to(dest);
        self.sign_keys.to_bytes().encode_to(dest);
        self.asset_id_witness.encode_to(dest);
    }
}

impl Decode for SecAccount {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let enc_keys = EncryptionKeys::decode(input)?;
        let sign_keys = <[u8; schnorrkel::KEYPAIR_LENGTH]>::decode(input)?;
        let sign_keys = SigningKeys::from_bytes(&sign_keys)
            .map_err(|_| CodecError::from("SecAccount.sign_keys is invalid"))?;
        let asset_id_witness = CommitmentWitness::decode(input)?;

        Ok(SecAccount {
            enc_keys,
            sign_keys,
            asset_id_witness,
        })
    }
}

/// Wrapper for both the secret and public account info
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Account {
    pub pblc: PubAccount,
    pub scrt: SecAccount,
}

impl Account {
    /// Utility method that can decrypt the the balance of an account.
    /// Note that this decryption is not constant time.
    pub fn decrypt_balance(&self) -> Fallible<Balance> {
        let balance = self
            .scrt
            .enc_keys
            .scrt
            .decrypt(&self.pblc.enc_balance.elgamal_cipher)?;

        Ok(Balance::from(balance))
    }
}

/// The interface for the account creation.
pub trait AccountCreatorInitializer {
    /// Creates a public account for a user and initializes the balance to zero.
    /// Corresponds to `CreateAccount` method of the MERCAT paper.
    /// This function assumes that the given input `account_id` is unique.
    fn create<T: RngCore + CryptoRng>(
        &self,
        tx_id: u32,
        scrt: &SecAccount,
        valid_asset_ids: &Vec<Scalar>,
        account_id: u32,
        rng: &mut T,
    ) -> Fallible<PubAccountTx>;
}

/// The interface for the verifying the account creation.
pub trait AccountCreatorVerifier {
    /// Called by the validators to ensure that the account was created correctly.
    fn verify(&self, account: &PubAccountTx, valid_asset_ids: &Vec<Scalar>) -> Fallible<()>;
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

/// Holds the public portion of an asset issuance transaction after initialization.
/// This can be placed on the chain.
#[derive(Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct AssetTxContent {
    pub account_id: u32,
    pub enc_asset_id: EncryptedAssetId,
    pub enc_amount_for_mdtr: EncryptedAmount,
    pub memo: AssetMemo,
    pub asset_id_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
    pub balance_wellformedness_proof: WellformednessProof,
    pub balance_correctness_proof: CorrectnessProof,
    pub auditors_payload: Vec<AuditorPayload>,
}

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct InitializedAssetTx {
    pub content: AssetTxContent,
    pub sig: Signature,
}

impl Encode for InitializedAssetTx {
    #[inline]
    fn size_hint(&self) -> usize {
        self.content.size_hint() + schnorrkel::SIGNATURE_LENGTH
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.content.encode_to(dest);
        self.sig.to_bytes().encode_to(dest);
    }
}

impl Decode for InitializedAssetTx {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let content = <AssetTxContent>::decode(input)?;
        let sig = <[u8; schnorrkel::SIGNATURE_LENGTH]>::decode(input)?;
        let sig = Signature::from_bytes(&sig)
            .map_err(|_| CodecError::from("InitializedAssetTx::sig is invalid"))?;

        Ok(InitializedAssetTx { content, sig })
    }
}

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct JustifiedAssetTx {
    pub content: InitializedAssetTx,
    pub sig: Signature,
}

impl Encode for JustifiedAssetTx {
    #[inline]
    fn size_hint(&self) -> usize {
        self.content.size_hint() + schnorrkel::SIGNATURE_LENGTH
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.content.encode_to(dest);
        self.sig.to_bytes().encode_to(dest);
    }
}

impl Decode for JustifiedAssetTx {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let content = <InitializedAssetTx>::decode(input)?;
        let sig = <[u8; schnorrkel::SIGNATURE_LENGTH]>::decode(input)?;
        let sig = Signature::from_bytes(&sig)
            .map_err(|_| CodecError::from("JustifiedAssetTx::sig is invalid"))?;

        Ok(JustifiedAssetTx { content, sig })
    }
}

/// The interface for the confidential asset issuance transaction.
pub trait AssetTransactionIssuer {
    /// Initializes a confidential asset issue transaction. Note that the returning
    /// values of this function contain sensitive information. Corresponds
    /// to `CreateAssetIssuanceTx` MERCAT whitepaper.
    fn initialize_asset_transaction<T: RngCore + CryptoRng>(
        &self,
        tx_id: u32,
        issr_account: &Account,
        mdtr_pub_key: &EncryptionPubKey,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<InitializedAssetTx>;
}

pub trait AssetTransactionMediator {
    /// Justifies and processes a confidential asset issue transaction. This includes checking
    /// the transaction for proper auditors payload. This method is called
    /// by mediator. Corresponds to `JustifyAssetTx` of MERCAT paper.
    fn justify_asset_transaction(
        &self,
        initialized_asset_tx: InitializedAssetTx,
        issr_pub_account: &PubAccount,
        mdtr_enc_keys: &EncryptionKeys,
        mdtr_sign_keys: &SigningKeys,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
    ) -> Fallible<JustifiedAssetTx>;
}

pub trait AssetTransactionVerifier {
    /// Called by validators to verify the justification and processing of the transaction.
    fn verify_asset_transaction(
        &self,
        justified_asset_tx: &JustifiedAssetTx,
        issr_account: PubAccount,
        mdtr_enc_pub_key: &EncryptionPubKey,
        mdtr_sign_pub_key: &SigningPubKey,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
    ) -> Fallible<PubAccount>;
}

pub trait AssetTransactionAuditor {
    /// Verify the initialized, and justified transactions.
    /// Audit the sender's encrypted amount.
    fn audit_asset_transaction(
        &self,
        justified_asset_tx: &JustifiedAssetTx,
        issuer_account: &PubAccount,
        mdtr_enc_pub_key: &EncryptionPubKey,
        mdtr_sign_pub_key: &SigningPubKey,
        auditor_enc_keys: &(u32, EncryptionKeys),
    ) -> Fallible<()>;
}

// -------------------------------------------------------------------------------------
// -                       Confidential Transfer Transaction                           -
// -------------------------------------------------------------------------------------

#[derive(Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct AuditorPayload {
    pub auditor_id: u32,
    pub encrypted_amount: EncryptedAmount,
    pub amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
}

/// Holds the memo for confidential transaction sent by the sender.
#[derive(Default, Clone, Copy, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct TransferTxMemo {
    pub sndr_account_id: u32,
    pub rcvr_account_id: u32,
    pub enc_amount_using_sndr: EncryptedAmount,
    pub enc_amount_using_rcvr: EncryptedAmount,
    pub refreshed_enc_balance: EncryptedAmount,
    pub refreshed_enc_asset_id: EncryptedAssetId,
    pub enc_asset_id_using_rcvr: EncryptedAssetId,
    pub enc_asset_id_for_mdtr: EncryptedAssetId,
    pub enc_amount_for_mdtr: EncryptedAmount,
    pub tx_id: u32,
}

/// Holds the proofs and memo of the confidential transaction sent by the sender.
#[derive(Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct InitializedTransferTxContent {
    pub amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
    pub non_neg_amount_proof: InRangeProof,
    pub enough_fund_proof: InRangeProof,
    pub memo: TransferTxMemo,
    pub asset_id_equal_cipher_with_sndr_rcvr_keys_proof: CipherEqualDifferentPubKeyProof,
    pub balance_refreshed_same_proof: CipherEqualSamePubKeyProof,
    pub asset_id_refreshed_same_proof: CipherEqualSamePubKeyProof,
    pub asset_id_correctness_proof: CorrectnessProof,
    pub amount_correctness_proof: CorrectnessProof,
    pub auditors_payload: Vec<AuditorPayload>,
}

/// Wrapper for the initial transaction data and its signature.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct InitializedTransferTx {
    pub content: InitializedTransferTxContent,
    pub sig: Signature,
}

impl Encode for InitializedTransferTx {
    #[inline]
    fn size_hint(&self) -> usize {
        self.content.size_hint() + schnorrkel::SIGNATURE_LENGTH
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.content.encode_to(dest);
        self.sig.to_bytes().encode_to(dest);
    }
}

impl Decode for InitializedTransferTx {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let content = <InitializedTransferTxContent>::decode(input)?;
        let sig = <[u8; schnorrkel::SIGNATURE_LENGTH]>::decode(input)?;
        let sig = Signature::from_bytes(&sig)
            .map_err(|_| CodecError::from("InitializedTx::sig is invalid"))?;

        Ok(InitializedTransferTx { content, sig })
    }
}

/// Holds the initial transaction data and the proof of equality of asset ids
/// prepared by the receiver.
#[derive(Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct FinalizedTransferTxContent {
    pub init_data: InitializedTransferTx,
    pub tx_id: u32,
    pub asset_id_from_sndr_equal_to_rcvr_proof: CipherEqualSamePubKeyProof,
}

/// Wrapper for the contents and the signature of the content sent by the
/// receiver of the transaction.
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct FinalizedTransferTx {
    pub content: FinalizedTransferTxContent,
    pub sig: Signature,
}

impl Encode for FinalizedTransferTx {
    #[inline]
    fn size_hint(&self) -> usize {
        self.content.size_hint() + schnorrkel::SIGNATURE_LENGTH
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.content.encode_to(dest);
        self.sig.to_bytes().encode_to(dest);
    }
}

impl Decode for FinalizedTransferTx {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let content = <FinalizedTransferTxContent>::decode(input)?;
        let sig = <[u8; schnorrkel::SIGNATURE_LENGTH]>::decode(input)?;
        let sig = Signature::from_bytes(&sig)
            .map_err(|_| CodecError::from("FinalizedTx::sig is invalid"))?;

        Ok(FinalizedTransferTx { content, sig })
    }
}

/// Wrapper for the contents, auditors' payload, and the signature of the justified and finalized
/// transaction.
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct JustifiedTransferTx {
    pub content: FinalizedTransferTx,
    pub sig: Signature,
}

impl Encode for JustifiedTransferTx {
    #[inline]
    fn size_hint(&self) -> usize {
        self.content.size_hint() + schnorrkel::SIGNATURE_LENGTH
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.content.encode_to(dest);
        self.sig.to_bytes().encode_to(dest);
    }
}

impl Decode for JustifiedTransferTx {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let content = <FinalizedTransferTx>::decode(input)?;
        let sig = <[u8; schnorrkel::SIGNATURE_LENGTH]>::decode(input)?;
        let sig = Signature::from_bytes(&sig)
            .map_err(|_| CodecError::from("JustifiedTx::sig is invalid"))?;

        Ok(JustifiedTransferTx { content, sig })
    }
}

/// The interface for confidential transaction.
pub trait TransferTransactionSender {
    /// This is called by the sender of a confidential transaction. The outputs
    /// can be safely placed on the chain. It corresponds to `CreateCTX` function of
    /// MERCAT paper.
    fn create_transaction<T: RngCore + CryptoRng>(
        &self,
        tx_id: u32,
        sndr_account: &Account,
        rcvr_pub_account: &PubAccount,
        mdtr_pub_key: &EncryptionPubKey,
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
        tx_id: u32,
        initialized_transaction: InitializedTransferTx,
        sndr_sign_pub_key: &SigningPubKey,
        rcvr_account: Account,
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<FinalizedTransferTx>;
}

pub trait TransferTransactionMediator {
    /// Justify the transaction by mediator.
    fn justify_transaction<R: RngCore + CryptoRng>(
        &self,
        finalized_transaction: FinalizedTransferTx,
        mdtr_enc_keys: &EncryptionKeys,
        mdtr_sign_keys: &SigningKeys,
        sndr_account: &PubAccount,
        rcvr_account: &PubAccount,
        pending_balance: EncryptedAmount,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
        asset_id_hint: AssetId,
        rng: &mut R,
    ) -> Fallible<JustifiedTransferTx>;
}

pub trait TransferTransactionVerifier {
    /// Verify the initialized, finalized, and justified transactions.
    /// Returns the updated sender and receiver accounts.
    fn verify_transaction<R: RngCore + CryptoRng>(
        &self,
        justified_transaction: &JustifiedTransferTx,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        mdtr_sign_pub_key: &SigningPubKey,
        pending_balance: EncryptedAmount,
        auditors_enc_pub_keys: &[(u32, EncryptionPubKey)],
        rng: &mut R,
    ) -> Fallible<(PubAccount, PubAccount)>;
}

pub trait TransferTransactionAuditor {
    /// Verify the initialized, finalized, and justified transactions.
    /// Audit the sender's encrypted amount.
    fn audit_transaction(
        &self,
        justified_transaction: &JustifiedTransferTx,
        sndr_account: &PubAccount,
        rcvr_account: &PubAccount,
        mdtr_sign_pub_key: &SigningPubKey,
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
    _sig: Signature,
}

/// Holds the memo for reversal of the confidential transaction sent by the mediator.
pub struct ReversedTransferTxMemo {
    _enc_amount_using_rcvr: EncryptedAmount,
    _enc_refreshed_amount: EncryptedAmount,
    _enc_asset_id_using_rcvr: EncryptedAssetId,
}

pub trait ReversedTransferTransactionMediator {
    /// This function is called by the mediator to reverse and process the reversal of
    /// the transaction. It corresponds to `ReverseCTX` of the MERCAT paper.
    fn create(
        &self,
        transaction_final_data: FinalizedTransferTx,
        mdtr_enc_keys: EncryptionSecKey,
        mdtr_sign_keys: SigningKeys,
        state: TransferTxState,
    ) -> Fallible<(ReversedTransferTx, TransferTxState)>;
}

pub trait ReversedTransferTransactionVerifier {
    /// This function is called by validators to verify the reversal and processing of the
    /// reversal transaction.
    fn verify(
        &self,
        reverse_transaction_data: ReversedTransferTx,
        mdtr_sign_pub_key: SigningPubKey,
        state: TransferTxState,
    ) -> Fallible<TransferTxState>;
}
