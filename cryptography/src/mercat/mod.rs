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
        wellformedness_proof::WellformednessProof, CipherText, CommitmentWitness, ElgamalPublicKey,
        ElgamalSecretKey,
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
use sp_std::{convert::From, fmt, mem, vec::Vec};

// -------------------------------------------------------------------------------------
// -                                  Constants                                        -
// -------------------------------------------------------------------------------------

const EXPONENT: u32 = 8; // TODO: change to 8. CRYP-112
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
pub type EncryptedAmount = CipherText;

/// Asset memo holds the contents of an asset issuance transaction.
pub type AssetMemo = EncryptedAmount;

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
    pub timestamp: u64,
}

impl AccountMemo {
    pub fn new(owner_enc_pub_key: EncryptionPubKey, owner_sign_pub_key: SigningPubKey) -> Self {
        AccountMemo {
            owner_enc_pub_key,
            owner_sign_pub_key,
            timestamp: 0,
        }
    }
}

impl Encode for AccountMemo {
    #[inline]
    fn size_hint(&self) -> usize {
        self.owner_enc_pub_key.size_hint()
            + schnorrkel::PUBLIC_KEY_LENGTH  // owner_sign_pub_key
            + mem::size_of::<i64>() // timestamp
    }

    #[inline]
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.owner_enc_pub_key.encode_to(dest);
        self.owner_sign_pub_key.to_bytes().encode_to(dest);
        self.timestamp.encode_to(dest);
    }
}

impl Decode for AccountMemo {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let owner_enc_pub_key = <EncryptionPubKey>::decode(input)?;

        let owner_sign_pub_key = <[u8; schnorrkel::PUBLIC_KEY_LENGTH]>::decode(input)?;
        let owner_sign_pub_key = SigningPubKey::from_bytes(&owner_sign_pub_key)
            .map_err(|_| CodecError::from("AccountMemo.owner_sign_pub_key is invalid"))?;

        let timestamp = <u64>::decode(input)?;

        Ok(AccountMemo {
            owner_enc_pub_key,
            owner_sign_pub_key,
            timestamp,
        })
    }
}

/// Holds contents of the public portion of an account which can be safely put on the chain.
#[derive(Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct PubAccountContent {
    pub id: u32,
    pub enc_asset_id: EncryptedAssetId,
    pub enc_balance: EncryptedAmount,
    pub asset_wellformedness_proof: WellformednessProof,
    pub asset_membership_proof: MembershipProof,
    pub initial_balance_correctness_proof: CorrectnessProof,
    pub memo: AccountMemo,
}

/// Wrapper for the account content and signature.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct PubAccount {
    pub content: PubAccountContent,
    pub initial_sig: Signature,
}

impl Encode for PubAccount {
    #[inline]
    fn size_hint(&self) -> usize {
        self.content.size_hint() + schnorrkel::SIGNATURE_LENGTH // initial_sig
    }

    #[inline]
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.content.encode_to(dest);
        self.initial_sig.to_bytes().encode_to(dest);
    }
}

impl Decode for PubAccount {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let content = PubAccountContent::decode(input)?;
        let initial_sig = <[u8; schnorrkel::SIGNATURE_LENGTH]>::decode(input)?;
        let initial_sig = Signature::from_bytes(&initial_sig)
            .map_err(|_| CodecError::from("PubAccount.initial_sig is invalid"))?;

        Ok(PubAccount {
            content,
            initial_sig,
        })
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
    pub fn decrypt_balance(&self) -> Fallible<Balance> {
        let balance = self
            .scrt
            .enc_keys
            .scrt
            .decrypt(&self.pblc.content.enc_balance)?;

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
        scrt: SecAccount,
        valid_asset_ids: &Vec<Scalar>,
        account_id: u32,
        rng: &mut T,
    ) -> Fallible<Account>;
}

/// The interface for the verifying the account creation.
pub trait AccountCreatorVerifier {
    /// Called by the validators to ensure that the account was created correctly.
    fn verify(&self, account: &PubAccount, valid_asset_ids: &Vec<Scalar>) -> Fallible<()>;
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
/// confidentional asset issuance transaction.
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AssetTxState {
    Initialization(TxSubstate),
    Justification(TxSubstate),
}

impl fmt::Display for AssetTxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetTxState::Initialization(substate) => write!(f, "initialization_{}", substate),
            AssetTxState::Justification(substate) => write!(f, "justification_{}", substate),
        }
    }
}

impl core::fmt::Debug for AssetTxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetTxState::Initialization(substate) => write!(f, "initialization_{}", substate),
            AssetTxState::Justification(substate) => write!(f, "justification_{}", substate),
        }
    }
}

/// Represents the four states (initialized, justified, finalized, reversed) of a
/// confidentional transaction.
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TxState {
    Initialization(TxSubstate),
    Finalization(TxSubstate),
    Justification(TxSubstate),
    Reversal(TxSubstate),
}

impl fmt::Display for TxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxState::Initialization(substate) => write!(f, "initialization_{}", substate),
            TxState::Finalization(substate) => write!(f, "finalization_{}", substate),
            TxState::Justification(substate) => write!(f, "justification_{}", substate),
            TxState::Reversal(substate) => write!(f, "reversal_{}", substate),
        }
    }
}

impl core::fmt::Debug for TxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxState::Initialization(substate) => write!(f, "initialization_{}", substate),
            TxState::Finalization(substate) => write!(f, "finalization_{}", substate),
            TxState::Justification(substate) => write!(f, "justification_{}", substate),
            TxState::Reversal(substate) => write!(f, "reversal_{}", substate),
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
    account_id: u32,
    enc_asset_id: EncryptedAssetId,
    enc_amount: EncryptedAmount,
    memo: AssetMemo,
    asset_id_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
    balance_wellformedness_proof: WellformednessProof,
    balance_correctness_proof: CorrectnessProof,
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
    /// Initializes a confidentional asset issue transaction. Note that the returing
    /// values of this function contain sensitive information. Corresponds
    /// to `CreateAssetIssuanceTx` MERCAT whitepaper.
    fn initialize_asset_transaction<T: RngCore + CryptoRng>(
        &self,
        issr_account_id: u32,
        issr_account: &SecAccount,
        mdtr_pub_key: &EncryptionPubKey,
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<InitializedAssetTx>;
}

pub trait AssetTransactionMediator {
    /// Justifies and processes a confidential asset issue transaction. This method is called
    /// by mediator. Corresponds to `JustifyAssetTx` and `ProcessCTx` of MERCAT paper.
    /// If the trasaction is justified, it will be processed immediately and the updated account
    /// is returned.
    fn justify_asset_transaction(
        &self,
        initialized_asset_tx: InitializedAssetTx,
        issr_pub_account: &PubAccount,
        mdtr_enc_keys: &EncryptionKeys,
        mdtr_sign_keys: &SigningKeys,
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
    ) -> Fallible<PubAccount>;
}

// -------------------------------------------------------------------------------------
// -                            Confidential Transaction                               -
// -------------------------------------------------------------------------------------

/// Holds the memo for confidential transaction sent by the sender.
#[derive(Default, Clone, Copy, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct TxMemo {
    pub sndr_account_id: u32,
    pub rcvr_account_id: u32,
    pub enc_amount_using_sndr: EncryptedAmount,
    pub enc_amount_using_rcvr: EncryptedAmount,
    pub refreshed_enc_balance: EncryptedAmount,
    pub refreshed_enc_asset_id: EncryptedAssetId,
    pub enc_asset_id_using_rcvr: EncryptedAssetId,
    pub enc_asset_id_for_mdtr: EncryptedAssetId,
    pub enc_amount_for_mdtr: EncryptedAmount,
}

/// Holds the proofs and memo of the confidential transaction sent by the sender.
#[derive(Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct InititializedTxContent {
    pub amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
    pub non_neg_amount_proof: InRangeProof,
    pub enough_fund_proof: InRangeProof,
    pub memo: TxMemo,
    pub asset_id_equal_cipher_with_sndr_rcvr_keys_proof: CipherEqualDifferentPubKeyProof,
    pub balance_refreshed_same_proof: CipherEqualSamePubKeyProof,
    pub asset_id_refreshed_same_proof: CipherEqualSamePubKeyProof,
    pub asset_id_correctness_proof: CorrectnessProof,
    pub amount_correctness_proof: CorrectnessProof,
}

/// Wrapper for the initial transaction data and its signature.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct InitializedTx {
    pub content: InititializedTxContent,
    pub sig: Signature,
}

impl Encode for InitializedTx {
    #[inline]
    fn size_hint(&self) -> usize {
        self.content.size_hint() + schnorrkel::SIGNATURE_LENGTH
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.content.encode_to(dest);
        self.sig.to_bytes().encode_to(dest);
    }
}

impl Decode for InitializedTx {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let content = <InititializedTxContent>::decode(input)?;
        let sig = <[u8; schnorrkel::SIGNATURE_LENGTH]>::decode(input)?;
        let sig = Signature::from_bytes(&sig)
            .map_err(|_| CodecError::from("InitializedTx::sig is invalid"))?;

        Ok(InitializedTx { content, sig })
    }
}

/// Holds the initial transaction data and the proof of equality of asset ids
/// prepared by the receiver.
#[derive(Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct FinalizedTxContent {
    pub init_data: InitializedTx,
    pub asset_id_from_sndr_equal_to_rcvr_proof: CipherEqualSamePubKeyProof,
}

/// Wrapper for the contents and the signature of the content sent by the
/// receiver of the transaction.
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct FinalizedTx {
    pub content: FinalizedTxContent,
    pub sig: Signature,
}

impl Encode for FinalizedTx {
    #[inline]
    fn size_hint(&self) -> usize {
        self.content.size_hint() + schnorrkel::SIGNATURE_LENGTH
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.content.encode_to(dest);
        self.sig.to_bytes().encode_to(dest);
    }
}

impl Decode for FinalizedTx {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let content = <FinalizedTxContent>::decode(input)?;
        let sig = <[u8; schnorrkel::SIGNATURE_LENGTH]>::decode(input)?;
        let sig = Signature::from_bytes(&sig)
            .map_err(|_| CodecError::from("FinalizedTx::sig is invalid"))?;

        Ok(FinalizedTx { content, sig })
    }
}

/// Wrapper for the contents and the signature of the justified and finalized
/// transaction.
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct JustifiedTx {
    pub content: FinalizedTx,
    pub sig: Signature,
}

impl Encode for JustifiedTx {
    #[inline]
    fn size_hint(&self) -> usize {
        self.content.size_hint() + schnorrkel::SIGNATURE_LENGTH
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.content.encode_to(dest);
        self.sig.to_bytes().encode_to(dest);
    }
}

impl Decode for JustifiedTx {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let content = <FinalizedTx>::decode(input)?;
        let sig = <[u8; schnorrkel::SIGNATURE_LENGTH]>::decode(input)?;
        let sig = Signature::from_bytes(&sig)
            .map_err(|_| CodecError::from("JustifiedTx::sig is invalid"))?;

        Ok(JustifiedTx { content, sig })
    }
}

/// The interface for confidential transaction.
pub trait TransactionSender {
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
    ) -> Fallible<InitializedTx>;
}

pub trait TransactionReceiver {
    /// This function is called the receiver of the transaction to finalize and process
    /// the transaction. It corresponds to `FinalizeCTX` and `ProcessCTX` functions
    /// of the MERCAT paper.
    fn finalize_transaction<T: RngCore + CryptoRng>(
        &self,
        initialized_transaction: InitializedTx,
        sndr_sign_pub_key: &SigningPubKey,
        rcvr_account: Account,
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<FinalizedTx>;
}

pub trait TransactionMediator {
    /// Justify the transaction by mediator.
    fn justify_transaction(
        &self,
        finalized_transaction: FinalizedTx,
        mdtr_enc_keys: &EncryptionKeys,
        mdtr_sign_keys: &SigningKeys,
        sndr_sign_pub_key: &SigningPubKey,
        rcvr_sign_pub_key: &SigningPubKey,
        // NOTE: without this, decryption takes a very long time. Since asset id to scalar takes the hash of the asset id array.
        asset_id_hint: AssetId,
    ) -> Fallible<JustifiedTx>;
}

pub trait TransactionVerifier {
    /// Verify the intialized, finalized, and justified transactions.
    /// Returns the updated sender and receiver accounts.
    fn verify_transaction<R: RngCore + CryptoRng>(
        &self,
        justified_transaction: &JustifiedTx,
        sndr_account: PubAccount,
        rcvr_account: PubAccount,
        mdtr_sign_pub_key: &SigningPubKey,
        rng: &mut R,
    ) -> Fallible<(PubAccount, PubAccount)>;
}

// -------------------------------------------------------------------------------------
// -                         Reversal Confidential Transaction                         -
// -------------------------------------------------------------------------------------

/// Holds the public portion of the reversal transaction.
pub struct ReversedTx {
    _final_data: InitializedTx,
    _memo: ReversedTxMemo,
    _sig: Signature,
}

/// Holds the memo for reversal of the confidential transaction sent by the mediator.
pub struct ReversedTxMemo {
    _enc_amount_using_rcvr: EncryptedAmount,
    _enc_refreshed_amount: EncryptedAmount,
    _enc_asset_id_using_rcvr: EncryptedAssetId,
}

pub trait ReversedTransactionMediator {
    /// This function is called by the mediator to reverse and process the reversal of
    /// the transaction. It corresponds to `ReverseCTX` of the MERCAT paper.
    fn create(
        &self,
        transaction_final_data: FinalizedTx,
        mdtr_enc_keys: EncryptionSecKey,
        mdtr_sign_keys: SigningKeys,
        state: TxState,
    ) -> Fallible<(ReversedTx, TxState)>;
}

pub trait ReversedTransactionVerifier {
    /// This function is called by validators to verify the reversal and processing of the
    /// reversal transaction.
    fn verify(
        &self,
        reverse_transaction_data: ReversedTx,
        mdtr_sign_pub_key: SigningPubKey,
        state: TxState,
    ) -> Fallible<TxState>;
}
