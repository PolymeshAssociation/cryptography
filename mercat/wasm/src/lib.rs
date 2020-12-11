use base64;
use codec::{Decode, Encode};
use mercat::{
    account::{convert_asset_ids, AccountCreator},
    asset::AssetIssuer,
    cryptography_core::{
        asset_proofs::{CipherText, CommitmentWitness, ElgamalPublicKey, ElgamalSecretKey},
        curve25519_dalek::scalar::Scalar,
        errors::Error,
        AssetId,
    },
    transaction::{CtxMediator, CtxReceiver, CtxSender},
    Account as MercatAccount, AccountCreatorInitializer, AssetTransactionIssuer, EncryptedAmount,
    EncryptionKeys, FinalizedTransferTx, InitializedTransferTx,
    MediatorAccount as MercatMediatorAccount, PubAccount as MercatPubAccount, SecAccount,
    TransferTransactionMediator, TransferTransactionReceiver, TransferTransactionSender,
};
use rand_core::OsRng;
use wasm_bindgen::prelude::*;

pub type PlainHex = String;

pub type Base64 = String;

#[wasm_bindgen]
pub struct CreatAccountOutput {
    secret_account: Base64,
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
    public_account: Base64,
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
    pub fn public_account(&self) -> Base64 {
        self.public_account.clone()
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
pub struct ValidAssetIds {
    plain_hex_ids: Vec<PlainHex>,
}

#[wasm_bindgen]
pub struct Account {
    secret_account: Base64,
    public_account: PubAccount,
}

#[wasm_bindgen]
pub struct MediatorAccount {
    secret: Base64,
}

#[wasm_bindgen]
pub struct PubAccount {
    account_id: Base64,
    public_key: Base64,
}

impl PubAccount {
    fn to_mercat(&self) -> MercatPubAccount {
        let decoded = base64::decode(&self.public_key).unwrap();
        let owner_enc_pub_key = ElgamalPublicKey::decode(&mut &decoded[..]).unwrap();

        let decoded = base64::decode(&self.account_id).unwrap();
        let enc_asset_id = CipherText::decode(&mut &decoded[..]).unwrap();

        MercatPubAccount {
            owner_enc_pub_key,
            enc_asset_id,
        }
    }
}

impl Account {
    fn to_mercat(&self) -> MercatAccount {
        let decoded = base64::decode(&self.secret_account).unwrap();
        let secret = SecAccount::decode(&mut &decoded[..]).unwrap();

        MercatAccount {
            secret,
            public: self.public_account.to_mercat(),
        }
    }
}

impl MediatorAccount {
    fn to_mercat(&self) -> MercatMediatorAccount {
        let decoded = base64::decode(&self.secret).unwrap();
        MercatMediatorAccount::decode(&mut &decoded[..]).unwrap()
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
pub fn create_account(
    valid_ticker_ids: ValidAssetIds,
    ticker_id: PlainHex,
) -> Result<CreatAccountOutput, JsValue> {
    let mut rng = OsRng;

    let secret_account = create_secret_account(&mut rng, ticker_id.clone()).unwrap(); // TODO
    let valid_asset_ids: Vec<AssetId> = valid_ticker_ids
        .plain_hex_ids
        .into_iter()
        .map(|ticker_id| {
            let mut asset_id = [0u8; 12];
            let decoded = hex::decode(ticker_id).unwrap(); // TODO
            asset_id[..decoded.len()].copy_from_slice(&decoded);
            Ok(AssetId { id: asset_id })
        })
        .collect::<Result<Vec<AssetId>, Error>>()
        .unwrap();
    let valid_asset_ids = convert_asset_ids(valid_asset_ids);
    let account_tx = AccountCreator
        .create(&secret_account, &valid_asset_ids, &mut rng)
        .unwrap();
    let account_id = account_tx.pub_account.enc_asset_id.clone();

    Ok(CreatAccountOutput {
        secret_account: base64::encode(secret_account.encode()),
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
        public: mediator_elg_secret_key.get_public_key().into(),
        secret: mediator_elg_secret_key.into(),
    };

    CreatMediatorAccountOutput {
        public_account: base64::encode(mediator_enc_key.public.encode()),
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
pub fn mint_asset(amount: u32, issuer_account: Account) -> MintAssetOutput {
    let mut rng = OsRng;
    let asset_tx = AssetIssuer
        .initialize_asset_transaction(&issuer_account.to_mercat(), &[], amount, &mut rng)
        .unwrap(); // TODO

    MintAssetOutput {
        asset_tx: base64::encode(asset_tx.encode()),
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
pub fn create_transaction(
    amount: u32,
    sender_account: Account,
    encrypted_pending_balance: Base64,
    receiver_public_account: PubAccount,
    mediator_public_key: Base64,
) -> CreateTransactionOutput {
    let mut rng = OsRng;

    let decoded = base64::decode(encrypted_pending_balance).unwrap();
    let pending_balance = CipherText::decode(&mut &decoded[..]).unwrap();

    let decoded = base64::decode(mediator_public_key).unwrap();
    let mediator_public_key = ElgamalPublicKey::decode(&mut &decoded[..]).unwrap();

    let init_tx = CtxSender
        .create_transaction(
            &sender_account.to_mercat(),
            &pending_balance,
            &receiver_public_account.to_mercat(),
            &mediator_public_key,
            &[],
            amount,
            &mut rng,
        )
        .unwrap();

    CreateTransactionOutput {
        init_tx: base64::encode(init_tx.encode()),
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
pub fn finalize_transaction(
    amount: u32,
    init_tx: Base64,
    receiver_account: Account,
) -> FinalizedTransactionOutput {
    let mut rng = OsRng;

    let decoded = base64::decode(init_tx).unwrap();
    let tx = InitializedTransferTx::decode(&mut &decoded[..]).unwrap();

    let finalized_tx = CtxReceiver
        .finalize_transaction(tx, receiver_account.to_mercat(), amount, &mut rng)
        .unwrap();

    FinalizedTransactionOutput {
        finalized_tx: base64::encode(finalized_tx.encode()),
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
pub fn justify_transaction(
    finalized_tx: Base64,
    mediator_account: MediatorAccount,
    sender_public_account: PubAccount,
    sender_encrypted_pending_balance: Base64,
    receiver_public_account: PubAccount,
    ticker_id: PlainHex,
) -> JustifiedTransactionOutput {
    let mut rng = OsRng;

    let decoded = base64::decode(finalized_tx).unwrap();
    let finalized_tx = FinalizedTransferTx::decode(&mut &decoded[..]).unwrap();

    let mut asset_id = [0u8; 12];
    let decoded = hex::decode(ticker_id).unwrap();
    asset_id[..decoded.len()].copy_from_slice(&decoded);
    let asset_id = AssetId { id: asset_id };

    let decoded = base64::decode(sender_encrypted_pending_balance).unwrap();
    let sender_balance = EncryptedAmount::decode(&mut &decoded[..]).unwrap();

    let justified_tx = CtxMediator
        .justify_transaction(
            finalized_tx,
            &mediator_account.to_mercat().encryption_key,
            &sender_public_account.to_mercat(),
            &sender_balance,
            &receiver_public_account.to_mercat(),
            &[],
            asset_id,
            &mut rng,
        )
        .unwrap();

    JustifiedTransactionOutput {
        justified_tx: base64::encode(justified_tx.encode()),
    }
}

fn create_secret_account(rng: &mut OsRng, ticker_id: String) -> Result<SecAccount, Error> {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
        public: elg_pub.into(),
        secret: elg_secret.into(),
    };

    let mut asset_id = [0u8; 12];
    let decoded = hex::decode(ticker_id).unwrap();
    asset_id[..decoded.len()].copy_from_slice(&decoded);

    let asset_id = AssetId { id: asset_id };
    let asset_id_witness = CommitmentWitness::new(asset_id.clone().into(), Scalar::random(rng));

    Ok(SecAccount {
        enc_keys,
        asset_id_witness,
    })
}
