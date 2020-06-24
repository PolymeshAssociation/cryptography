mod input;
use codec::Decode;
use cryptography::mercat::{
    account::AccountValidator, asset::AssetTxIssueValidator, AccountCreatorVerifier, AccountMemo,
    AssetTransactionFinalizeAndProcessVerifier, AssetTransactionInitializeVerifier, AssetTxState,
    PubAccount, PubAssetTxData, PubJustifiedAssetTxData, TxSubstate,
};
use env_logger;
use input::{parse_input, CLI};
use log::info;
use mercat_common::{
    errors::Error, get_asset_ids, init_print_logger, load_object, save_object, transaction_file,
    Instruction, INIT_STATE, JUSTIFY_STATE, ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE,
    VALIDATED_PUBLIC_ACCOUNT_FILE,
};
use metrics::timing;
use std::time::Instant;

fn asset_issuance_init_started(
    instruction: Instruction,
    mdtr_account: &AccountMemo,
    issr_pub_account: &PubAccount,
) -> AssetTxState {
    let tx = PubAssetTxData::decode(&mut &instruction.data[..]).unwrap();
    let validator = AssetTxIssueValidator {};
    let state = validator
        .verify_initialization(
            &tx,
            instruction.state,
            &issr_pub_account,
            &mdtr_account.owner_enc_pub_key,
        )
        .expect("Failed to validate a transaction"); // todo add the transaction id maybe?
                                                     // assert_eq!(state, AssetTxState::Initialization(TxSubstate::Validated));
    state
}

fn asset_issuance_justification_started(
    instruction: Instruction,
    mdtr_account: &AccountMemo,
    issr_pub_account: &PubAccount,
) -> AssetTxState {
    let tx = PubJustifiedAssetTxData::decode(&mut &instruction.data[..]).unwrap();
    let validator = AssetTxIssueValidator {};
    let state = validator
        .verify_justification(&tx, issr_pub_account, &mdtr_account.owner_sign_pub_key)
        .expect("Failed to validate a transaction"); // todo add the transaction id maybe?
                                                     // assert_eq!(state, AssetTxState::Initialization(TxSubstate::Validated));
    state
}

fn validate_asset_issuance(cfg: input::AssetIssuanceInfo) {
    // println!("state: {} vs {:?}", AssetTxState::Initialization(TxSubstate::Started), cfg.state);
    // let state = AssetTxState::decode(&mut &cfg.state.as_bytes()[..]).unwrap();
    let state = match cfg.state.as_str() {
        // move this string literal to common.
        INIT_STATE => AssetTxState::Initialization(TxSubstate::Started),
        JUSTIFY_STATE => AssetTxState::Justification(TxSubstate::Started),
        _ => panic!("Invalid state"),
    };

    let mut instruction: Instruction = load_object(
        cfg.db_dir.clone(),
        ON_CHAIN_DIR,
        &cfg.issuer,
        &transaction_file(cfg.tx_id, state),
    )
    .unwrap_or_else(|error| panic!("Failed to deserialize the instruction: {}", error));

    let mediator_account: AccountMemo = load_object(
        cfg.db_dir.clone(),
        ON_CHAIN_DIR,
        &cfg.mediator,
        PUBLIC_ACCOUNT_FILE,
    )
    .unwrap_or_else(|error| panic!("Failed to deserialize the instruction: {}", error));

    let issuer_account: PubAccount = load_object(
        cfg.db_dir.clone(),
        ON_CHAIN_DIR,
        &cfg.issuer,
        VALIDATED_PUBLIC_ACCOUNT_FILE,
    )
    .unwrap_or_else(|error| panic!("Failed to load the validated public account: {}", error));

    let result = match instruction.state {
        AssetTxState::Initialization(TxSubstate::Started) => {
            println!("Asset issuance initialization instruction.");
            asset_issuance_init_started(instruction.clone(), &mediator_account, &issuer_account)
        }
        AssetTxState::Justification(TxSubstate::Started) => {
            println!("Asset issuance justification instruction.");
            asset_issuance_justification_started(
                instruction.clone(),
                &mediator_account,
                &issuer_account,
            )
        }
        _ => {
            panic!("Instruction not supported!");
        }
    };
    // todo: this should have happened inside the library. the wierdness...
    instruction.state = result;
    save_object(
        cfg.db_dir.clone(),
        ON_CHAIN_DIR,
        &cfg.issuer,
        &transaction_file(cfg.tx_id, result),
        &instruction,
    )
    .unwrap();
}

fn validate_account(cfg: input::AccountCreationInfo) -> Result<(), Error> {
    let user_account: PubAccount = load_object(
        cfg.db_dir.clone(),
        ON_CHAIN_DIR,
        &cfg.user,
        PUBLIC_ACCOUNT_FILE,
    )?;

    let valid_asset_ids = get_asset_ids(cfg.db_dir.clone())?;

    let account_vldtr = AccountValidator {};
    account_vldtr
        .verify(&user_account, &valid_asset_ids)
        .unwrap_or_else(|error| panic!("Failed to deserialize the instruction: {}", error));

    // On success save the public account as validated.
    save_object(
        cfg.db_dir,
        ON_CHAIN_DIR,
        &cfg.user,
        &VALIDATED_PUBLIC_ACCOUNT_FILE,
        &user_account,
    )?;

    Ok(())
}

fn main() {
    info!("Starting the program.");
    env_logger::init();
    init_print_logger();

    let parse_arg_timer = Instant::now();
    let args = parse_input().unwrap();
    timing!("account.argument_parse", parse_arg_timer, Instant::now());

    match args {
        CLI::ValidateIssuance(cfg) => validate_asset_issuance(cfg),
        CLI::ValidateAccount(cfg) => validate_account(cfg).unwrap(),
    };
    info!("The program finished successfully.");
}
