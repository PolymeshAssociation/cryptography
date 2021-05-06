use codec::{Decode, Encode};
use confidential_identity::{CddClaimData, CddId};
use private_identity_audit::{
    uuid_to_scalar, CommittedSetGenerator, CommittedUids, PrivateUids, ProofGenerator,
    ProofVerifier, Prover, Verifier, VerifierSecrets, VerifierSetGenerator, ZKPFinalResponse,
    ZKPInitialmessage,
};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{convert::Into, str::FromStr};
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

// ------------------------------------------------------------------------------------
// -                                  Type Definitions                                -
// ------------------------------------------------------------------------------------

/// A base64 encoded string.
pub type Base64 = String;

/// Investor's DID.
type InvestorDID = [u8; 32];

/// Unique ID in UUIDv4 format.
type UniqueID = [u8; 16];

#[derive(Debug, Serialize, Deserialize)]
pub struct RawCddClaimData {
    pub investor_did: InvestorDID,
    pub investor_unique_id: UniqueID,
}

#[wasm_bindgen]
pub struct VerificationResult {
    results: Vec<Fallible<()>>,
}

#[wasm_bindgen]
impl VerificationResult {
    #[wasm_bindgen(method, structural, indexing_getter)]
    pub fn get(&self, i: usize) -> bool {
        if let Ok(_) = self.results[i] {
            return true;
        } else {
            return false;
        }
    }
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> usize {
        self.results.len()
    }
}

#[wasm_bindgen]
pub struct CommittedSetOutput {
    verifier_secrets: Base64,
    committed_uids: Base64,
}

#[wasm_bindgen]
impl CommittedSetOutput {
    #[wasm_bindgen(getter)]
    pub fn verifier_secrets(&self) -> Base64 {
        self.verifier_secrets.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn committed_uids(&self) -> Base64 {
        self.committed_uids.clone()
    }
}

#[wasm_bindgen]
pub struct ProofsOutput {
    initial_messages: Base64,
    final_responses: Base64,
    committed_uids: Base64,
}

#[wasm_bindgen]
impl ProofsOutput {
    #[wasm_bindgen(getter)]
    pub fn initial_messages(&self) -> Base64 {
        self.initial_messages.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn final_responses(&self) -> Base64 {
        self.final_responses.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn committed_uids(&self) -> Base64 {
        self.committed_uids.clone()
    }
}

// ------------------------------------------------------------------------------------
// -                                     Error Types                                  -
// ------------------------------------------------------------------------------------

#[wasm_bindgen]
#[derive(Serialize)]
pub enum WasmError {
    GenerateInitialMessageError,
    GenerateCommittedSetError,
    GenerateChallengeResponseError,
    Base64DecodingError,
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

/// The first leg of the protocol from PUIS to CDD Provider.
#[wasm_bindgen]
pub fn generate_committed_set(
    private_uuids: String,
    min_set_size: usize,
    seed: String,
) -> Fallible<CommittedSetOutput> {
    let uuids: Vec<String> = serde_json::from_str(&private_uuids)
        .map_err(|error| format!("Failed to deserialize the private_uuids: {}", error))?;

    let uuids = uuids
        .into_iter()
        .map(|uuid| {
            Uuid::from_str(&uuid)
                .map_err(|err| format!("Deserialization error for UUIDs: {}", err).into())
        })
        .collect::<Result<Vec<Uuid>, JsValue>>()?;
    let uuids = PrivateUids(uuids.into_iter().map(|uuid| uuid_to_scalar(uuid)).collect());

    let min_set_size = if min_set_size > 0 {
        Some(min_set_size)
    } else {
        None
    };

    let seed: [u8; 32] = serde_json::from_str(&seed)
        .map_err(|error| format!("Failed to deserialize the seed: {}", error))?;
    let mut rng = StdRng::from_seed(seed);

    let results = VerifierSetGenerator::generate_committed_set(uuids, min_set_size, &mut rng)
        .map_err(|_| WasmError::GenerateCommittedSetError)?;

    Ok(CommittedSetOutput {
        verifier_secrets: base64::encode(results.0.encode()),
        committed_uids: base64::encode(results.1.encode()),
    })
}

/// The second leg of the protocol from CDD Provider to PUIS.
#[wasm_bindgen]
pub fn generate_proofs(
    cdd_claims: String,
    committed_uids: Base64,
    seed: String,
) -> Fallible<ProofsOutput> {
    let raw_cdd_claims: Vec<RawCddClaimData> = serde_json::from_str(&cdd_claims)
        .map_err(|error| format!("Failed to deserialize the cdd_claims: {}", error))?;
    let cdd_claims: Vec<CddClaimData> = raw_cdd_claims
        .into_iter()
        .map(|raw| CddClaimData::new(&raw.investor_did, &raw.investor_unique_id))
        .collect();
    let committed_uids: CommittedUids = decode_base64(committed_uids)?;

    let seed: [u8; 32] = serde_json::from_str(&seed)
        .map_err(|error| format!("Failed to deserialize the seed: {}", error))?;
    let mut rng = StdRng::from_seed(seed);
    let results = Prover::generate_proofs(&cdd_claims, &committed_uids, &mut rng)
        .map_err(|_| WasmError::GenerateInitialMessageError)?;

    Ok(ProofsOutput {
        initial_messages: base64::encode(results.0.encode()),
        final_responses: base64::encode(results.1.encode()),
        committed_uids: base64::encode(results.2.encode()),
    })
}

/// The last step of the protocol in which PUIS verifies the proofs.
#[wasm_bindgen]
pub fn verify_proofs(
    initial_messages: Base64,
    final_responses: Base64,
    cdd_ids: String,
    verifier_secrets: Base64,
    re_committed_uids: Base64,
) -> Fallible<VerificationResult> {
    let initial_message: Vec<ZKPInitialmessage> = decode_base64(initial_messages)?;
    let final_response: Vec<ZKPFinalResponse> = decode_base64(final_responses)?;
    let cdd_ids: Vec<CddId> = serde_json::from_str(&cdd_ids)
        .map_err(|error| format!("Failed to deserialize the cdd_ids: {}", error))?;
    let verifier_secrets: VerifierSecrets = decode_base64(verifier_secrets)?;
    let re_committed_uids: CommittedUids = decode_base64(re_committed_uids)?;

    let results: Vec<Fallible<()>> = Verifier::verify_proofs(
        &initial_message,
        &final_response,
        &cdd_ids,
        &verifier_secrets,
        &re_committed_uids,
    )
    .into_iter()
    .map(|result| result.map_err(|error| format!("Proof verification error: {}", error).into()))
    .collect();

    Ok(VerificationResult { results })
}

// ------------------------------------------------------------------------------------
// -                               Internal Functions                                 -
// ------------------------------------------------------------------------------------

fn decode_base64<T: Decode>(data: Base64) -> Fallible<T> {
    let decoded = base64::decode(data).map_err(|_| WasmError::Base64DecodingError)?;
    T::decode(&mut &decoded[..]).map_err(|err| format!("Deserialization error: {}", err).into())
}
