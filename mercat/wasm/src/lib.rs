use codec::{Decode, Encode};
use mercat::{
    account::{convert_asset_ids, AccountCreator},
    asset::AssetIssuer,
    cryptography_core::{
        asset_proofs::{CipherText, CommitmentWitness, ElgamalPublicKey, ElgamalSecretKey},
        curve25519_dalek::scalar::Scalar,
        AssetId,
    },
    transaction::{CtxMediator, CtxReceiver, CtxSender},
    Account as MercatAccount, AccountCreatorInitializer, AssetTransactionIssuer, EncryptedAmount,
    EncryptionKeys, FinalizedTransferTx, InitializedAssetTx, InitializedTransferTx,
    MediatorAccount as MercatMediatorAccount, PubAccount as MercatPubAccount, PubAccountTx,
    SecAccount, TransferTransactionMediator, TransferTransactionReceiver,
    TransferTransactionSender,
};
use rand_core::OsRng;
use serde::Serialize;
use serde_json;
use std::convert::Into;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

// ------------------------------------------------------------------------------------
// -                                  Type Definitions                                -
// ------------------------------------------------------------------------------------

pub type PlainHex = String;

pub type Base64 = String;

#[wasm_bindgen]
pub struct CreatAccountOutput {
    secret_account: Base64,
    public_key: Base64,
    account_id: Base64,
    account_tx: Base64,
}

#[wasm_bindgen]
impl CreatAccountOutput {
    #[wasm_bindgen(getter)]
    pub fn secret_account(&self) -> Base64 {
        self.secret_account.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Base64 {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn account_id(&self) -> Base64 {
        self.account_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn account_tx(&self) -> Base64 {
        self.account_tx.clone()
    }
}

#[wasm_bindgen]
pub struct CreatMediatorAccountOutput {
    secret_account: MediatorAccount,
    public_key: Base64,
}

#[wasm_bindgen]
impl CreatMediatorAccountOutput {
    #[wasm_bindgen(getter)]
    pub fn secret_account(&self) -> MediatorAccount {
        MediatorAccount {
            secret: self.secret_account.secret.clone(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Base64 {
        self.public_key.clone()
    }
}

#[wasm_bindgen]
pub struct CreateTransactionOutput {
    init_tx: Base64,
}

#[wasm_bindgen]
impl CreateTransactionOutput {
    #[wasm_bindgen(getter)]
    pub fn init_tx(&self) -> Base64 {
        self.init_tx.clone()
    }
}

#[wasm_bindgen]
pub struct FinalizedTransactionOutput {
    finalized_tx: Base64,
}

#[wasm_bindgen]
impl FinalizedTransactionOutput {
    #[wasm_bindgen(getter)]
    pub fn finalized_tx(&self) -> Base64 {
        self.finalized_tx.clone()
    }
}

#[wasm_bindgen]
pub struct JustifiedTransactionOutput {
    justified_tx: Base64,
}

#[wasm_bindgen]
impl JustifiedTransactionOutput {
    #[wasm_bindgen(getter)]
    pub fn justified_tx(&self) -> Base64 {
        self.justified_tx.clone()
    }
}

#[wasm_bindgen]
pub struct MintAssetOutput {
    asset_tx: Base64,
}

#[wasm_bindgen]
impl MintAssetOutput {
    #[wasm_bindgen(getter)]
    pub fn asset_tx(&self) -> Base64 {
        self.asset_tx.clone()
    }
}

#[wasm_bindgen]
pub struct MediatorAccount {
    secret: Base64,
}

#[wasm_bindgen]
impl MediatorAccount {
    #[wasm_bindgen(constructor)]
    pub fn new(secret: Base64) -> Self {
        Self { secret }
    }
}

#[wasm_bindgen]
pub struct Account {
    secret_account: Base64,
    public_account: PubAccount,
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen(constructor)]
    pub fn new(secret_account: Base64, public_account: PubAccount) -> Self {
        Self {
            secret_account,
            public_account,
        }
    }

    fn to_mercat(&self) -> Fallible<MercatAccount> {
        Ok(MercatAccount {
            secret: decode::<SecAccount>(self.secret_account.clone())?,
            public: self.public_account.to_mercat()?,
        })
    }
}

#[wasm_bindgen]
pub struct PubAccount {
    account_id: Base64,
    public_key: Base64,
}

#[wasm_bindgen]
impl PubAccount {
    #[wasm_bindgen(constructor)]
    pub fn new(account_id: Base64, public_key: Base64) -> Self {
        Self {
            account_id,
            public_key,
        }
    }

    fn to_mercat(&self) -> Fallible<MercatPubAccount> {
        Ok(MercatPubAccount {
            owner_enc_pub_key: decode::<ElgamalPublicKey>(self.public_key.clone())?,
            enc_asset_id: decode::<CipherText>(self.account_id.clone())?,
        })
    }
}

impl MediatorAccount {
    fn to_mercat(&self) -> Fallible<MercatMediatorAccount> {
        decode::<MercatMediatorAccount>(self.secret.clone())
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
    Base64DecodingError,
    HexDecodingError,
    PlainTickerIdsError,
    DecryptionError,
}

impl From<WasmError> for JsValue {
    fn from(e: WasmError) -> JsValue {
        if let Ok(msg) = serde_json::to_string(&e) {
            msg.into()
        } else {
            "Failed to serialized the error to string!".into()
        }
    }
}

type Fallible<T> = Result<T, JsValue>;

// ------------------------------------------------------------------------------------
// -                                     Public API                                   -
// ------------------------------------------------------------------------------------

/// TODO
///
/// # Arguments
/// * `todo`: todo
///
/// # Outputs
/// * `todo`: todo
///
/// # Errors
/// * todo
#[wasm_bindgen]
pub fn create_account(
    valid_ticker_ids: JsValue,
    ticker_id: PlainHex,
) -> Fallible<CreatAccountOutput> {
    let mut rng = OsRng;
    let valid_ticker_ids: Vec<String> = valid_ticker_ids
        .into_serde()
        .map_err(|_| WasmError::PlainTickerIdsError)?;

    let secret_account = create_secret_account(&mut rng, ticker_id)?;
    let valid_asset_ids: Vec<AssetId> = valid_ticker_ids
        .into_iter()
        .map(ticker_id_to_asset_id)
        .collect::<Fallible<Vec<AssetId>>>()?;
    let valid_asset_ids = convert_asset_ids(valid_asset_ids);
    let account_tx: PubAccountTx = AccountCreator
        .create(&secret_account, &valid_asset_ids, &mut rng)
        .map_err(|_| WasmError::AccountCreationError)?;
    let account_id = account_tx.pub_account.enc_asset_id;

    Ok(CreatAccountOutput {
        secret_account: base64::encode(secret_account.encode()),
        public_key: base64::encode(secret_account.enc_keys.public.encode()),
        account_id: base64::encode(account_id.encode()),
        account_tx: base64::encode(account_tx.encode()),
    })
}

/// TODO
///
/// # Arguments
/// * `todo`: todo
///
/// # Outputs
/// * `todo`: todo
///
/// # Errors
/// * todo
#[wasm_bindgen]
pub fn create_mediator_account() -> CreatMediatorAccountOutput {
    let mut rng = OsRng;

    let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
    let mediator_enc_key = EncryptionKeys {
        public: mediator_elg_secret_key.get_public_key(),
        secret: mediator_elg_secret_key,
    };

    CreatMediatorAccountOutput {
        public_key: base64::encode(mediator_enc_key.public.encode()),
        secret_account: MediatorAccount {
            secret: base64::encode(
                MercatMediatorAccount {
                    encryption_key: mediator_enc_key,
                }
                .encode(),
            ),
        },
    }
}

/// TODO
///
/// # Arguments
/// * `todo`: todo
///
/// # Outputs
/// * `todo`: todo
///
/// # Errors
/// * todo
#[wasm_bindgen]
pub fn mint_asset(amount: u32, issuer_account: Account) -> Fallible<MintAssetOutput> {
    let mut rng = OsRng;
    let asset_tx: InitializedAssetTx = AssetIssuer
        .initialize_asset_transaction(&issuer_account.to_mercat()?, &[], amount, &mut rng)
        .map_err(|_| WasmError::AssetIssuanceError)?;

    Ok(MintAssetOutput {
        asset_tx: base64::encode(asset_tx.encode()),
    })
}

/// TODO
///
/// # Arguments
/// * `todo`: todo
///
/// # Outputs
/// * `todo`: todo
///
/// # Errors
/// * todo
#[wasm_bindgen]
pub fn create_transaction(
    amount: u32,
    sender_account: Account,
    encrypted_pending_balance: Base64,
    receiver_public_account: PubAccount,
    mediator_public_key: Base64,
) -> Fallible<CreateTransactionOutput> {
    let mut rng = OsRng;

    let init_tx = CtxSender
        .create_transaction(
            &sender_account.to_mercat()?,
            &decode::<CipherText>(encrypted_pending_balance)?,
            &receiver_public_account.to_mercat()?,
            &decode::<ElgamalPublicKey>(mediator_public_key)?,
            &[],
            amount,
            &mut rng,
        )
        .map_err(|_| WasmError::TransactionCreationError)?;

    Ok(CreateTransactionOutput {
        init_tx: base64::encode(init_tx.encode()),
    })
}

/// TODO
///
/// # Arguments
/// * `todo`: todo
///
/// # Outputs
/// * `todo`: todo
///
/// # Errors
/// * todo
#[wasm_bindgen]
pub fn finalize_transaction(
    amount: u32,
    init_tx: Base64,
    receiver_account: Account,
) -> Fallible<FinalizedTransactionOutput> {
    let mut rng = OsRng;

    let finalized_tx = CtxReceiver
        .finalize_transaction(
            decode::<InitializedTransferTx>(init_tx)?,
            receiver_account.to_mercat()?,
            amount,
            &mut rng,
        )
        .map_err(|_| WasmError::TransactionFinalizationError)?;

    Ok(FinalizedTransactionOutput {
        finalized_tx: base64::encode(finalized_tx.encode()),
    })
}

/// TODO
///
/// # Arguments
/// * `todo`: todo
///
/// # Outputs
/// * `todo`: todo
///
/// # Errors
/// * todo
#[wasm_bindgen]
pub fn justify_transaction(
    finalized_tx: Base64,
    mediator_account: MediatorAccount,
    sender_public_account: PubAccount,
    sender_encrypted_pending_balance: Base64,
    receiver_public_account: PubAccount,
    ticker_id: PlainHex,
) -> Fallible<JustifiedTransactionOutput> {
    let mut rng = OsRng;

    let justified_tx = CtxMediator
        .justify_transaction(
            decode::<FinalizedTransferTx>(finalized_tx)?,
            &mediator_account.to_mercat()?.encryption_key,
            &sender_public_account.to_mercat()?,
            &decode::<EncryptedAmount>(sender_encrypted_pending_balance)?,
            &receiver_public_account.to_mercat()?,
            &[],
            ticker_id_to_asset_id(ticker_id)?,
            &mut rng,
        )
        .map_err(|_| WasmError::TransactionJustificationError)?;

    Ok(JustifiedTransactionOutput {
        justified_tx: base64::encode(justified_tx.encode()),
    })
}

/// TODO
///
/// # Arguments
/// * `todo`: todo
///
/// # Outputs
/// * `todo`: todo
///
/// # Errors
/// * todo
#[wasm_bindgen]
pub fn decrypt(encrypted_value: Base64, account: Account) -> Fallible<u32> {
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

fn decode<T: Decode>(data: Base64) -> Fallible<T> {
    if let Ok(decoded) = base64::decode(data) {
        if let Ok(ret) = T::decode(&mut &decoded[..]) {
            return Ok(ret);
        }
        return Err(WasmError::DeserializationError.into());
    }

    Err(WasmError::Base64DecodingError.into())
}

fn ticker_id_to_asset_id(ticker_id: PlainHex) -> Fallible<AssetId> {
    let mut asset_id = [0u8; 12];
    let decoded = hex::decode(ticker_id).map_err(|_| WasmError::HexDecodingError)?;
    asset_id[..decoded.len()].copy_from_slice(&decoded);
    Ok(AssetId { id: asset_id })
}

fn create_secret_account(rng: &mut OsRng, ticker_id: String) -> Fallible<SecAccount> {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
        public: elg_pub,
        secret: elg_secret,
    };

    let mut asset_id = [0u8; 12];
    let decoded = hex::decode(ticker_id).map_err(|_| WasmError::HexDecodingError)?;
    asset_id[..decoded.len()].copy_from_slice(&decoded);

    let asset_id = AssetId { id: asset_id };
    let asset_id_witness = CommitmentWitness::new(asset_id.into(), Scalar::random(rng));

    Ok(SecAccount {
        enc_keys,
        asset_id_witness,
    })
}
