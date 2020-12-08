//! Statement: q=G^x
//! ZKP(q, G):
//!   1. P -> V: A = G^r
//!   2. V -> P: c
//!   3. P -> V: s = r + c*x
//!   4. V: G^s == A * q^c
//!
//! Statement: q=H^y*F^z
//! ZKP(q, G):
//!   1. P -> V: A = H^r1 * F^r2
//!   2. V -> P: c
//!   3. P -> V: s1 = r1 + c*y, s2 = r2 + c*z
//!   4. V: H^s1 * F^s2 == A * q^c
//!

use cryptography_core::{
    asset_proofs::{
        encryption_proofs::{
            AssetProofProver, AssetProofProverAwaitingChallenge, AssetProofVerifier, ZKPChallenge,
            ZKProofResponse,
        },
        transcript::{TranscriptProtocol, UpdateTranscript},
    },
    curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar},
    errors::{ErrorKind as CoreErrorKind, Fallible as CoreFallible},
};
use merlin::{Transcript, TranscriptRng};
use rand_core::{CryptoRng, RngCore};

/// The domain label for the wellformedness proof.
pub const WELLFORMEDNESS_PROOF_FINAL_RESPONSE_LABEL: &[u8] =
    b"PIAL_PolymathWellformednessFinalResponse";
/// The domain label for the challenge.
pub const WELLFORMEDNESS_PROOF_CHALLENGE_LABEL: &[u8] =
    b"PIAL_PolymathWellformednessProofChallenge";

pub struct WellformednessInitialMessage {
    a: RistrettoPoint,
}

pub struct WellformednessFinalResponse {
    s: Vec<Scalar>,
}

impl UpdateTranscript for WellformednessInitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> CoreFallible<()> {
        transcript.append_domain_separator(WELLFORMEDNESS_PROOF_CHALLENGE_LABEL);
        transcript.append_validated_point(b"A", &self.a.compress())?;
        Ok(())
    }
}

/// Holds the non-interactive proofs of wellformedness, equivalent of L_enc of the MERCAT paper.
pub type WellformednessProof =
    ZKProofResponse<WellformednessInitialMessage, WellformednessFinalResponse>;

#[derive(Clone, Debug)]
pub struct WellformednessProver {
    /// The secret commitment witness.
    secrets: Vec<Scalar>,
    /// The randomness generate in the first round.
    rands: Vec<Scalar>,
}

#[derive(Clone)]
pub struct WellformednessProverAwaitingChallenge<'a> {
    /// The secret commitment witness.
    pub secrets: Vec<Scalar>,

    /// The Pedersen generators.
    pub generators: &'a Vec<RistrettoPoint>,
}

impl<'a> AssetProofProverAwaitingChallenge for WellformednessProverAwaitingChallenge<'a> {
    type ZKInitialMessage = WellformednessInitialMessage;
    type ZKFinalResponse = WellformednessFinalResponse;
    type ZKProver = WellformednessProver;

    fn create_transcript_rng<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        transcript: &Transcript,
    ) -> TranscriptRng {
        (&self.secrets)
            .into_iter()
            .fold(transcript.build_rng(), |transcript_rng, secret| {
                transcript_rng.rekey_with_witness_bytes(b"secret_value", secret.as_bytes())
            })
            .finalize(rng)
    }

    fn generate_initial_message(
        &self,
        rng: &mut TranscriptRng,
    ) -> (Self::ZKProver, Self::ZKInitialMessage) {
        let rands: Vec<Scalar> = vec![0; self.generators.len()]
            .into_iter()
            .map(|_| Scalar::random(rng))
            .collect();
        let a = self
            .generators
            .clone()
            .into_iter()
            .zip(&rands)
            .map(|(gen, rand)| gen * rand)
            .fold_first(|v1, v2| v1 + v2)
            .unwrap();
        (
            WellformednessProver {
                secrets: self.secrets.clone(),
                rands,
            },
            WellformednessInitialMessage { a },
        )
    }
}

impl AssetProofProver<WellformednessFinalResponse> for WellformednessProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> WellformednessFinalResponse {
        let s = (&self.rands)
            .into_iter()
            .zip(&self.secrets)
            .map(|(rand, secret)| rand + c.x() * secret)
            .collect();
        WellformednessFinalResponse { s }
    }
}

#[derive(Copy, Clone)]
pub struct WellformednessVerifier<'a> {
    pub statement: RistrettoPoint,
    pub generators: &'a Vec<RistrettoPoint>,
}

impl<'a> AssetProofVerifier for WellformednessVerifier<'a> {
    type ZKInitialMessage = WellformednessInitialMessage;
    type ZKFinalResponse = WellformednessFinalResponse;

    fn verify(
        &self,
        challenge: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        response: &Self::ZKFinalResponse,
    ) -> CoreFallible<()> {
        let lhs = self
            .generators
            .into_iter()
            .zip(&response.s)
            .map(|(gen, s)| gen * s)
            .fold_first(|v1, v2| v1 + v2)
            .ok_or(CoreErrorKind::WellformednessFinalResponseVerificationError { check: 1 })?;
        let rhs = initial_message.a + self.statement * challenge.x();

        // TODO replace with ErrorKind and ensure
        assert_eq!(lhs, rhs);

        Ok(())
    }
}

//#[cfg(test)]
//mod tests {
//    extern crate wasm_bindgen_test;
//    use super::*;
//    use crate::asset_proofs::encryption_proofs::{
//        single_property_prover, single_property_verifier,
//    };
//    use crate::asset_proofs::*;
//    use rand::{rngs::StdRng, SeedableRng};
//    use sp_std::prelude::*;
//    use wasm_bindgen_test::*;
//
//    const SEED_1: [u8; 32] = [42u8; 32];
//
//    #[test]
//    #[wasm_bindgen_test]
//    fn test_wellformedness_proof() {
//        let gens = PedersenGens::default();
//        let mut rng = StdRng::from_seed(SEED_1);
//        let secret_value = 42u32;
//
//        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
//        let pub_key = elg_secret.get_public_key();
//        let (w, cipher) = pub_key.encrypt_value(secret_value.into(), &mut rng);
//
//        let prover = WellformednessProverAwaitingChallenge {
//            pub_key,
//            w: w.clone(),
//            pc_gens: &gens,
//        };
//        let verifier = WellformednessVerifier {
//            pub_key,
//            cipher,
//            pc_gens: &gens,
//        };
//        let mut dealer_transcript = Transcript::new(WELLFORMEDNESS_PROOF_FINAL_RESPONSE_LABEL);
//
//        // ------------------------------- Interactive case
//        // Positive tests
//        // 1st round
//        let mut transcript_rng = prover.create_transcript_rng(&mut rng, &dealer_transcript);
//        let (prover, initial_message) = prover.generate_initial_message(&mut transcript_rng);
//
//        // 2nd round
//        initial_message
//            .update_transcript(&mut dealer_transcript)
//            .unwrap();
//        let challenge = dealer_transcript
//            .scalar_challenge(WELLFORMEDNESS_PROOF_CHALLENGE_LABEL)
//            .unwrap();
//
//        // 3rd round
//        let final_response = prover.apply_challenge(&challenge);
//
//        // 4th round
//        // in the interactive case, verifier is the dealer and therefore, the challenge is saved
//        // on the verifier side and passed to this function.
//        let result = verifier.verify(&challenge, &initial_message, &final_response);
//        assert!(result.is_ok());
//
//        // Negative tests
//        let bad_initial_message = WellformednessInitialMessage::default();
//        let result = verifier.verify(&challenge, &bad_initial_message, &final_response);
//        assert_err!(
//            result,
//            ErrorKind::WellformednessFinalResponseVerificationError { check: 1 }
//        );
//
//        let bad_final_response = WellformednessFinalResponse {
//            z1: Scalar::default(),
//            z2: Scalar::default(),
//        };
//        let result = verifier.verify(&challenge, &initial_message, &bad_final_response);
//        assert_err!(
//            result,
//            ErrorKind::WellformednessFinalResponseVerificationError { check: 1 }
//        );
//
//        // ------------------------------- Non-interactive case
//        let prover = WellformednessProverAwaitingChallenge {
//            pub_key,
//            w: w,
//            pc_gens: &gens,
//        };
//        let verifier = WellformednessVerifier {
//            pub_key,
//            cipher,
//            pc_gens: &gens,
//        };
//
//        // 1st to 3rd rounds
//        let (initial_message, final_response) = single_property_prover::<
//            StdRng,
//            WellformednessProverAwaitingChallenge,
//        >(prover, &mut rng)
//        .unwrap();
//
//        // Positive test
//        assert!(
//            // 4th round
//            single_property_verifier(&verifier, (initial_message, final_response)).is_ok()
//        );
//
//        // Negative tests
//        let bad_initial_message = WellformednessInitialMessage::default();
//        assert_err!(
//            // 4th round
//            single_property_verifier(&verifier, (bad_initial_message, final_response)),
//            ErrorKind::WellformednessFinalResponseVerificationError { check: 1 }
//        );
//
//        assert_err!(
//            // 4th round
//            single_property_verifier(&verifier, (initial_message, bad_final_response)),
//            ErrorKind::WellformednessFinalResponseVerificationError { check: 1 }
//        );
//    }
//
//    #[test]
//    #[wasm_bindgen_test]
//    fn serialize_deserialize_proof() {
//        let mut rng = StdRng::from_seed(SEED_1);
//        let secret_value = 42u32;
//        let rand_blind = Scalar::random(&mut rng);
//        let gens = PedersenGens::default();
//        let w = CommitmentWitness::new(secret_value.into(), rand_blind);
//        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
//        let pub_key = elg_secret.get_public_key();
//
//        let prover = WellformednessProverAwaitingChallenge {
//            pub_key,
//            w: w,
//            pc_gens: &gens,
//        };
//        let (initial_message, final_response) = encryption_proofs::single_property_prover::<
//            StdRng,
//            WellformednessProverAwaitingChallenge,
//        >(prover, &mut rng)
//        .unwrap();
//
//        let bytes = initial_message.encode();
//        let mut input = bytes.as_slice();
//        let recovered_initial_message = <WellformednessInitialMessage>::decode(&mut input).unwrap();
//        assert_eq!(recovered_initial_message, initial_message);
//
//        let bytes = final_response.encode();
//        let mut input = bytes.as_slice();
//        let recovered_final_response = <WellformednessFinalResponse>::decode(&mut input).unwrap();
//        assert_eq!(recovered_final_response, final_response);
//    }
//}
//

//use cryptography_core::curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
//use rand_core::{CryptoRng, RngCore};
//
//type ZKPChallenge = Scalar;
//
//pub struct WellformednessInitialMessage {
//    a: RistrettoPoint,
//    generators: Vec<RistrettoPoint>,
//    statement: RistrettoPoint,
//}
//
//pub struct WellformednessFinalResponse {
//    s: Vec<Scalar>,
//}
//
//pub struct WellformednessProver {
//    /// The randomness generate in the first round.
//    rands: Vec<Scalar>,
//    secrets: Vec<Scalar>,
//    initial_message: WellformednessInitialMessage,
//}
//
//impl WellformednessProver {
//    pub fn new<T: RngCore + CryptoRng>(
//        statement: RistrettoPoint,
//        secrets: Vec<Scalar>,
//        generators: Vec<RistrettoPoint>,
//        rng: &mut T,
//    ) -> Self {
//        let rands: Vec<Scalar> = vec![0; generators.len()]
//            .into_iter()
//            .map(|_| Scalar::random(rng))
//            .collect();
//        let a = generators
//            .clone()
//            .into_iter()
//            .zip(&rands)
//            .map(|(gen, rand)| gen * rand)
//            .fold_first(|v1, v2| v1 + v2)
//            .unwrap();
//
//        Self {
//            rands,
//            secrets,
//            initial_message: WellformednessInitialMessage {
//                a,
//                generators: generators.clone(),
//                statement,
//            },
//        }
//    }
//
//    pub fn apply_challenge(&self, c: ZKPChallenge) -> WellformednessFinalResponse {
//        let s = (&self.rands)
//            .into_iter()
//            .zip(&self.secrets)
//            .map(|(rand, secret)| rand + c * secret)
//            .collect();
//
//        WellformednessFinalResponse { s }
//    }
//}
//
//pub fn verify(
//    initial_message: WellformednessInitialMessage,
//    final_response: WellformednessFinalResponse,
//    c: ZKPChallenge,
//) -> bool {
//    let lhs = initial_message
//        .generators
//        .into_iter()
//        .zip(final_response.s)
//        .map(|(gen, s)| gen * s)
//        .fold_first(|v1, v2| v1 + v2)
//        .unwrap();
//    let rhs = initial_message.a + initial_message.statement * c;
//
//    lhs == rhs
//}
