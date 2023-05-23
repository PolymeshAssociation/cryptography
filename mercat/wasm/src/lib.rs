use codec::{Decode, Encode};
use mercat::{
    account::AccountCreator,
    asset::AssetIssuer,
    confidential_identity_core::{
        asset_proofs::{Balance, CipherText, ElgamalPublicKey, ElgamalSecretKey},
        curve25519_dalek::scalar::Scalar,
    },
    transaction::{CtxMediator, CtxReceiver, CtxSender},
    Account as MercatAccount, AccountCreatorInitializer, AmountSource, AssetTransactionIssuer,
    EncryptedAmount, EncryptionKeys, InitializedAssetTx, InitializedTransferTx,
    PubAccount as MercatPubAccount, PubAccountTx, SecAccount, TransferTransactionMediator,
    TransferTransactionReceiver, TransferTransactionSender,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore};
use serde::Serialize;
use serde_json;
use std::convert::{Into, TryInto};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

// ------------------------------------------------------------------------------------
// -                                  Type Definitions                                -
// ------------------------------------------------------------------------------------

/// Contains the secret and public account information of a party.
#[wasm_bindgen]
pub struct CreateAccountOutput {
    account: Account,
    account_tx: Vec<u8>,
}

#[wasm_bindgen]
impl CreateAccountOutput {
    /// The secret account must be kept confidential and not shared with anyone else.
    #[wasm_bindgen(getter)]
    pub fn account(&self) -> Account {
        self.account.clone()
    }

    /// The Zero Knowledge proofs of the account creation.
    #[wasm_bindgen(getter)]
    pub fn account_tx(&self) -> Vec<u8> {
        self.account_tx.clone()
    }
}

/// Contains the secret and public account information of a mediator.
#[wasm_bindgen]
pub struct CreateMediatorAccountOutput {
    account: Account,
}

#[wasm_bindgen]
impl CreateMediatorAccountOutput {
    /// The secret account must be kept confidential and not shared with anyone else.
    #[wasm_bindgen(getter)]
    pub fn account(&self) -> Account {
        self.account.clone()
    }
}

/// Contains the Zero Knowledge Proof of minting an asset by the issuer.
#[wasm_bindgen]
pub struct MintAssetOutput {
    asset_tx: Vec<u8>,
}

#[wasm_bindgen]
impl MintAssetOutput {
    /// The Zero Knowledge proofs of the asset minting.
    #[wasm_bindgen(getter)]
    pub fn asset_tx(&self) -> Vec<u8> {
        self.asset_tx.clone()
    }
}

/// Contains the Zero Knowledge Proof of initializing a confidential transaction by the sender.
#[wasm_bindgen]
pub struct CreateTransactionOutput {
    init_tx: Vec<u8>,
}

#[wasm_bindgen]
impl CreateTransactionOutput {
    /// The Zero Knowledge proofs of the initialized confidential transaction.
    #[wasm_bindgen(getter)]
    pub fn init_tx(&self) -> Vec<u8> {
        self.init_tx.clone()
    }
}

/// A wrapper around mercat account.
#[wasm_bindgen]
#[derive(Clone)]
pub struct Account {
    secret: SecAccount,
    public: PubAccount,
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen(constructor)]
    pub fn new(secret: Vec<u8>, public: PubAccount) -> Fallible<Account> {
        Ok(Self {
            secret: decode::<SecAccount>(secret)?,
            public,
        })
    }

    /// The secret account must be kept confidential and not shared with anyone else.
    #[wasm_bindgen(getter)]
    pub fn secret_account(&self) -> Vec<u8> {
        self.secret.encode()
    }

    /// The public account.
    #[wasm_bindgen(getter)]
    pub fn public_account(&self) -> PubAccount {
        self.public.clone()
    }

    fn enc_keys(&self) -> &EncryptionKeys {
        &self.secret.enc_keys
    }

    fn to_mercat(&self) -> Fallible<MercatAccount> {
        Ok(MercatAccount {
            secret: self.secret.clone(),
            public: self.public.to_mercat()?,
        })
    }
}

impl From<SecAccount> for Account {
    fn from(sec: SecAccount) -> Self {
        Self {
            public: PubAccount::from(&sec),
            secret: sec,
        }
    }
}

/// A wrapper around mercat public account.
#[wasm_bindgen]
#[derive(Clone)]
pub struct PubAccount {
    public_key: MercatPubAccount,
}

#[wasm_bindgen]
impl PubAccount {
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: Vec<u8>) -> Fallible<PubAccount> {
        Ok(Self {
            public_key: decode::<MercatPubAccount>(public_key)?,
        })
    }

    fn to_mercat(&self) -> Fallible<MercatPubAccount> {
        Ok(self.public_key.clone())
    }
}

impl From<&SecAccount> for PubAccount {
    fn from(sec: &SecAccount) -> Self {
        Self {
            public_key: MercatPubAccount {
                owner_enc_pub_key: sec.enc_keys.public.clone(),
            },
        }
    }
}

// ------------------------------------------------------------------------------------
// -                                     Error Types                                  -
// ------------------------------------------------------------------------------------

#[wasm_bindgen]
#[derive(Serialize)]
pub enum WasmError {
    AccountCreationError,
    AssetIssuanceError,
    TransactionCreationError,
    TransactionFinalizationError,
    TransactionJustificationError,
    DeserializationError,
    HexDecodingError,
    PlainTickerIdsError,
    DecryptionError,
    SeedTooShortError,
}

impl From<WasmError> for JsValue {
    fn from(e: WasmError) -> Self {
        serde_json::to_string(&e)
            .map(|msg| msg.into())
            .unwrap_or_else(|_| "Failed to serialized the error to string!".into())
    }
}

type Fallible<T> = Result<T, JsValue>;

fn get_rng(seed: &[u8]) -> Fallible<ChaCha20Rng> {
    if seed.len() < 32 {
        return Err(WasmError::SeedTooShortError.into());
    }
    Ok(ChaCha20Rng::from_seed(seed[0..32].try_into().unwrap()))
}

// ------------------------------------------------------------------------------------
// -                                     Public API                                   -
// ------------------------------------------------------------------------------------

/// Creates a mercat account. It is the responsibility of the caller
/// to properly store and safeguard the secret values returned by this function.
///
/// # Outputs
/// * `CreateAccountOutput`: Contains both the public and secret account information.
///
/// # Errors
/// * `AccountCreationError`: If mercat library throws an error while creating the account.
#[wasm_bindgen]
pub fn create_account(seed: &[u8]) -> Fallible<CreateAccountOutput> {
    let mut rng = get_rng(seed)?;

    let account = create_secret_account(&mut rng)?;
    let account_tx: PubAccountTx = AccountCreator
        .create(&account, &mut rng)
        .map_err(|_| WasmError::AccountCreationError)?;

    Ok(CreateAccountOutput {
        account: Account::from(account),
        account_tx: account_tx.encode(),
    })
}

/// Creates a mercat mediator account. It is the responsibility of the caller
/// to properly store and safeguard the secret values returned by this function.
///
/// # Arguments
///
/// # Outputs
/// * `CreateMediatorAccountOutput`: Contains the public and secret mediator account.
///
/// # Errors
#[wasm_bindgen]
pub fn create_mediator_account(seed: &[u8]) -> Fallible<CreateMediatorAccountOutput> {
    let mut rng = get_rng(seed)?;

    let account = create_secret_account(&mut rng)?;

    Ok(CreateMediatorAccountOutput {
        account: Account::from(account),
    })
}

/// Creates a Zero Knowledge Proof of minting a confidential asset.
///
/// # Arguments
/// * `amount`: An integer with a max value of `2^32` representing the mint amount.
/// * `issuer_account`: The mercat account. Can be obtained from `CreateAccountOutput.account`.
///
/// # Outputs
/// * `MintAssetOutput`: The ZKP of minting the asset.
///
/// # Errors
/// * `DeserializationError`: If the `issuer_account` cannot be deserialized to a mercat account.
#[wasm_bindgen]
pub fn mint_asset(
    seed: &[u8],
    amount: Balance,
    issuer_account: Account,
) -> Fallible<MintAssetOutput> {
    let mut rng = get_rng(seed)?;
    let asset_tx: InitializedAssetTx = AssetIssuer
        .initialize_asset_transaction(&issuer_account.to_mercat()?, &[], amount, &mut rng)
        .map_err(|_| WasmError::AssetIssuanceError)?;

    Ok(MintAssetOutput {
        asset_tx: asset_tx.encode(),
    })
}

/// Creates the ZKP for the initial phase of creating a confidential transaction. This function
/// is called by the sender and depends on secret information from the sender and public
/// information of the receiver and the mediator.
///
/// # Arguments
/// * `amount`: An integer with a max value of `2^32` representing the mint amount.
/// * `sender_account`: The mercat account. Can be obtained from `CreateAccountOutput.account`.
/// * `encrypted_pending_balance`: Sender's encrypted pending balance. Can be obtained from the
///                                chain.
/// * `receiver_public_account`: Receiver's public account. Can be obtained from the chain.
/// * `mediator_public_key`: Mediator's public key. Can be obtained from the chain.
///
/// # Outputs
/// * `CreateAccountOutput`: The ZKP of the initialized transaction.
///
/// # Errors
/// * `DeserializationError`: If either of the inputs cannot be deserialized to a mercat account.
/// * `TransactionCreationError`: If the mercat library throws an error when creating the proof.
#[wasm_bindgen]
pub fn create_transaction(
    seed: &[u8],
    amount: Balance,
    sender_account: Account,
    encrypted_pending_balance: Vec<u8>,
    pending_balance: Balance,
    receiver_public_account: PubAccount,
    mediator_public_key: Option<Vec<u8>>,
) -> Fallible<CreateTransactionOutput> {
    let mut rng = get_rng(seed)?;

    let mediator_public_key = match mediator_public_key {
        Some(key) => Some(decode::<ElgamalPublicKey>(key)?),
        _ => None,
    };
    let init_tx = CtxSender
        .create_transaction(
            &sender_account.to_mercat()?,
            &decode::<CipherText>(encrypted_pending_balance)?,
            pending_balance,
            &receiver_public_account.to_mercat()?,
            mediator_public_key.as_ref(),
            &[],
            amount,
            &mut rng,
        )
        .map_err(|_| WasmError::TransactionCreationError)?;

    Ok(CreateTransactionOutput {
        init_tx: init_tx.encode(),
    })
}

/// Creates the ZKP for the finalized phase of creating a confidential transaction. This function
/// is called by the receiver and depends on secret information from the receiver and public
/// information of the sender.
///
/// # Arguments
/// * `amount`: An integer with a max value of `2^32` representing the mint amount.
/// * `init_tx`: The initialized transaction proof. Can be obtained from the chain.
/// * `receiver_account`: The mercat account. Can be obtained from `CreateAccountOutput.account`.
///
/// # Errors
/// * `DeserializationError`: If either of the inputs cannot be deserialized to a mercat account.
/// * `TransactionFinalizationError`: If the mercat library throws an error when creating the proof.
#[wasm_bindgen]
pub fn finalize_transaction(
    amount: Balance,
    init_tx: Vec<u8>,
    receiver_account: Account,
) -> Fallible<()> {
    let init_tx = decode::<InitializedTransferTx>(init_tx)?;
    CtxReceiver
        .finalize_transaction(&init_tx, receiver_account.to_mercat()?, amount)
        .map_err(|_| WasmError::TransactionFinalizationError)?;

    Ok(())
}

/// Creates the ZKP for the justification phase of creating a confidential transaction.
/// This function is called by the mediator and depends on secret information from the
/// mediator and public information of the sender and the receiver.
///
/// # Arguments
/// * `finalized_tx`: The finalized transaction proof. Can be obtained from the chain.
/// * `mediator_account`: The secret portion of the mediator's account. Can be obtained from
///                       `CreateMediatorAccountOutput.secret_account`.
/// * `sender_public_account`: Sender's public account. Can be obtained from the chain.
/// * `sender_encrypted_pending_balance`: Sender's encrypted pending balance.
///                                       Can be obtained from the chain.
/// * `receiver_public_account`: Receiver's public account. Can be obtained from the chain.
///
/// # Errors
/// * `DeserializationError`: If either of the inputs cannot be deserialized to a mercat account.
/// * `TransactionJustificationError`: If the mercat library throws an error when creating the proof.
#[wasm_bindgen]
pub fn justify_transaction(
    seed: &[u8],
    init_tx: Vec<u8>,
    mediator_account: Account,
    sender_public_account: PubAccount,
    sender_encrypted_pending_balance: Vec<u8>,
    receiver_public_account: PubAccount,
    amount: Option<Balance>,
) -> Fallible<()> {
    let mut rng = get_rng(seed)?;

    let mediator_keys = mediator_account.enc_keys();
    let amount_source = match amount {
        Some(amount) => AmountSource::Amount(amount),
        None => AmountSource::Encrypted(mediator_keys),
    };
    let init_tx = decode::<InitializedTransferTx>(init_tx)?;
    CtxMediator
        .justify_transaction(
            &init_tx,
            amount_source,
            &sender_public_account.to_mercat()?,
            &decode::<EncryptedAmount>(sender_encrypted_pending_balance)?,
            &receiver_public_account.to_mercat()?,
            &[],
            &mut rng,
        )
        .map_err(|_| WasmError::TransactionJustificationError)?;

    Ok(())
}

/// Decrypts an `encrypted_value` given the secret account information.
///
/// # Arguments
/// * `encrypted_value`: The encrypted value.
/// * `account`: The mercat account. Can be obtained from `CreateAccountOutput.account`.
///
/// # Outputs
/// * `Balance`: The decrypted value.
///
/// # Errors
/// * `DeserializationError`: If either of the inputs cannot be deserialized to a mercat account.
/// * `DecryptionError`: If the mercat library throws an error while decrypting the value.
#[wasm_bindgen]
pub fn decrypt(encrypted_value: Vec<u8>, account: Account) -> Fallible<Balance> {
    let enc_balance = decode::<EncryptedAmount>(encrypted_value)?;
    let account = account.to_mercat()?;

    let decrypted_value = account
        .secret
        .enc_keys
        .secret
        .decrypt(&enc_balance)
        .map_err(|_| WasmError::DecryptionError)?;

    Ok(decrypted_value)
}

// ------------------------------------------------------------------------------------
// -                               Internal Functions                                 -
// ------------------------------------------------------------------------------------

fn decode<T: Decode>(data: Vec<u8>) -> Fallible<T> {
    T::decode(&mut &data[..]).map_err(|_| WasmError::DeserializationError.into())
}

fn create_secret_account<R: RngCore + CryptoRng>(rng: &mut R) -> Fallible<SecAccount> {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
        public: elg_pub,
        secret: elg_secret,
    };

    Ok(SecAccount { enc_keys })
}
