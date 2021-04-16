//! Provides interactive ZKP for statements of multiple base.
//!
//! Statement: q=G^x
//! ZKP(q; G):
//!   1. P -> V: A = G^r
//!   2. V -> P: c
//!   3. P -> V: s = r + c*x
//!   4. V: G^s == A * q^c
//!
//! Statement: q=H^y*F^z
//! ZKP(q; H, F):
//!   1. P -> V: A = H^r1 * F^r2
//!   2. V -> P: c
//!   3. P -> V: s1 = r1 + c*y, s2 = r2 + c*z
//!   4. V: H^s1 * F^s2 == A * q^c
//!
//! This library uses Fiat-Shamir heuristic to remove the need for sending the challenge.

use crate::errors::{ErrorKind, Fallible};
use crate::Challenge;
use codec::{Decode, Encode, Error as CodecError, Input, Output};
use cryptography_core::{
    asset_proofs::transcript::TranscriptProtocol,
    codec_wrapper::{RISTRETTO_POINT_SIZE, SCALAR_SIZE},
    curve25519_dalek::{
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
    },
};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sp_std::vec::Vec;

const PROOF_TRANSCRIPT_LABEL: &[u8] = b"PolymathPrivateIdentityAuditProof";
const PROOF_CHALLENGE_LABEL: &[u8] = b"PolymathPrivateIdentityAuditChallenge";

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InitialMessage {
    a: RistrettoPoint,
    pub generators: Vec<RistrettoPoint>,
}

impl InitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> Fallible<()> {
        transcript.append_domain_separator(PROOF_CHALLENGE_LABEL);
        transcript
            .append_validated_point(b"A", &self.a.compress())
            .map_err(|_| ErrorKind::IdentityPointError)?;
        Ok(())
    }
}

impl Encode for InitialMessage {
    #[inline]
    fn size_hint(&self) -> usize {
        RISTRETTO_POINT_SIZE + self.generators.len() * RISTRETTO_POINT_SIZE
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        let a = self.a.compress();
        let generators: Vec<[u8; RISTRETTO_POINT_SIZE]> = self
            .generators
            .iter()
            .map(|g| g.compress().to_bytes())
            .collect();

        a.as_bytes().encode_to(dest);
        generators.encode_to(dest);
    }
}

impl Decode for InitialMessage {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let (a, generators) =
            <([u8; RISTRETTO_POINT_SIZE], Vec<[u8; RISTRETTO_POINT_SIZE]>)>::decode(input)?;
        let a = CompressedRistretto(a)
            .decompress()
            .ok_or_else(|| CodecError::from("InitialMessage `a` point is invalid"))?;

        let generators: Vec<RistrettoPoint> = generators
            .into_iter()
            .map(|g| {
                CompressedRistretto(g)
                    .decompress()
                    .ok_or_else(|| CodecError::from("InitialMessage `generators` are invalid"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(InitialMessage { a, generators })
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FinalResponse {
    response: Vec<Scalar>,
}

impl Encode for FinalResponse {
    #[inline]
    fn size_hint(&self) -> usize {
        self.response.len() * SCALAR_SIZE
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        let response: Vec<[u8; SCALAR_SIZE]> = self.response.iter().map(|g| g.to_bytes()).collect();

        response.encode_to(dest);
    }
}

impl Decode for FinalResponse {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let response = <Vec<[u8; SCALAR_SIZE]>>::decode(input)?;

        let s: Vec<Scalar> = response.into_iter().map(Scalar::from_bits).collect();

        Ok(FinalResponse { response: s })
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Secrets {
    rands: Vec<Scalar>,
    secrets: Vec<Scalar>,
}

impl Encode for Secrets {
    #[inline]
    fn size_hint(&self) -> usize {
        self.rands.len() * SCALAR_SIZE + self.secrets.len() * SCALAR_SIZE
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        let rands: Vec<[u8; SCALAR_SIZE]> = self.rands.iter().map(|g| g.to_bytes()).collect();

        rands.encode_to(dest);

        let secrets: Vec<[u8; SCALAR_SIZE]> = self.secrets.iter().map(|g| g.to_bytes()).collect();

        secrets.encode_to(dest);
    }
}

impl Decode for Secrets {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let (rands, secrets) = <(Vec<[u8; SCALAR_SIZE]>, Vec<[u8; SCALAR_SIZE]>)>::decode(input)?;

        let rands: Vec<Scalar> = rands.into_iter().map(Scalar::from_bits).collect();

        let secrets: Vec<Scalar> = secrets.into_iter().map(Scalar::from_bits).collect();

        Ok(Secrets { rands, secrets })
    }
}

pub fn generate_initial_message<T: RngCore + CryptoRng>(
    secrets: Vec<Scalar>,
    generators: Vec<RistrettoPoint>,
    rng: &mut T,
) -> Fallible<(Secrets, InitialMessage)> {
    let rands: Vec<Scalar> = vec![0; generators.len()]
        .into_iter()
        .map(|_| Scalar::random(rng))
        .collect();
    let a = generators
        .iter()
        .zip(&rands)
        .map(|(gen, rand)| gen * rand)
        .reduce(|v1, v2| v1 + v2)
        .ok_or(ErrorKind::InitialMessageGenError)?;
    Ok((Secrets { rands, secrets }, InitialMessage { a, generators }))
}

pub fn apply_challenge(prover_secrets: &Secrets, c: &Challenge) -> FinalResponse {
    let s = (&prover_secrets.rands)
        .iter()
        .zip(&prover_secrets.secrets)
        .map(|(rand, &secret)| rand + (c.0) * secret)
        .collect();

    FinalResponse { response: s }
}

pub fn verify(
    initial_message: &InitialMessage,
    final_response: &FinalResponse,
    statement: &RistrettoPoint,
    c: &Challenge,
) -> bool {
    if let Some(lhs) = initial_message
        .generators
        .iter()
        .zip(&final_response.response)
        .map(|(gen, s)| gen * s)
        .reduce(|v1, v2| v1 + v2)
    {
        return lhs == initial_message.a + statement * (c.0);
    }

    false
}

pub fn non_interactive_prove<T: RngCore + CryptoRng>(
    secrets: Vec<Scalar>,
    generators: Vec<RistrettoPoint>,
    rng: &mut T,
) -> Fallible<(InitialMessage, FinalResponse)> {
    let mut transcript = Transcript::new(PROOF_TRANSCRIPT_LABEL);
    let mut transcript_rng_builder = transcript.build_rng();
    for secret in &secrets {
        transcript_rng_builder =
            transcript_rng_builder.rekey_with_witness_bytes(b"secret_value", &secret.to_bytes());
    }
    let mut transcript_rng = transcript_rng_builder.finalize(rng);

    let (secrets, initial_message) =
        generate_initial_message(secrets, generators, &mut transcript_rng)?;
    initial_message.update_transcript(&mut transcript)?;
    let mut buf = [0u8; 64];
    transcript.challenge_bytes(PROOF_CHALLENGE_LABEL, &mut buf);
    let challenge = Challenge(Scalar::from_bytes_mod_order_wide(&buf).into());
    let final_response = apply_challenge(&secrets, &challenge);

    Ok((initial_message, final_response))
}

pub fn non_interactive_verify(
    initial_message: &InitialMessage,
    final_response: &FinalResponse,
    statement: &RistrettoPoint,
) -> Fallible<bool> {
    let mut transcript = Transcript::new(PROOF_TRANSCRIPT_LABEL);
    initial_message.update_transcript(&mut transcript)?;
    let mut buf = [0u8; 64];
    transcript.challenge_bytes(PROOF_CHALLENGE_LABEL, &mut buf);
    let re_calculated_challenge = Challenge(Scalar::from_bytes_mod_order_wide(&buf).into());
    Ok(verify(
        &initial_message,
        &final_response,
        statement,
        &re_calculated_challenge,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptography_core::cdd_claim::{compute_cdd_id, CddClaimData};
    use cryptography_core::curve25519_dalek::traits::MultiscalarMul;
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::RngCore;

    #[test]
    fn test_zkp_multiple_base_proof() {
        let mut rng = StdRng::from_seed([42u8; 32]);
        let generators = vec![
            RistrettoPoint::random(&mut rng),
            RistrettoPoint::random(&mut rng),
        ];
        let secrets = vec![Scalar::random(&mut rng), Scalar::random(&mut rng)];
        let statement = RistrettoPoint::multiscalar_mul(&secrets, &generators);

        let (prover_secrets, initial_message) =
            generate_initial_message(secrets, generators, &mut rng).unwrap();

        let c = Challenge(Scalar::random(&mut rng).into());
        let final_response = apply_challenge(&prover_secrets, &c);

        // Positive test
        assert!(verify(&initial_message, &final_response, &statement, &c));

        // Negative test
        let statement = RistrettoPoint::random(&mut rng) * Scalar::random(&mut rng);
        let is_valid = verify(&initial_message, &final_response, &statement, &c);
        assert!(!is_valid);
    }

    #[test]
    fn test_zkp_cdd_id() {
        let mut rng = StdRng::from_seed([42u8; 32]);

        // Make a random did for the investor.
        let mut investor_did = [0u8; 32];
        rng.fill_bytes(&mut investor_did);

        // Make a random unique id for the investor.
        let mut investor_unique_id = [0u8; 32];
        rng.fill_bytes(&mut investor_unique_id);

        // Verifier shares one of its uids with the Prover.
        let claim = CddClaimData::new(&investor_did, &investor_unique_id);

        // Prover generates cdd_id and places it on the chain.
        let cdd_id = compute_cdd_id(&claim);

        let r = Scalar::random(&mut rng);
        let statement = cdd_id.0 * r;
        let (cdd_id_proof_secrets, cdd_id_proof) =
            generate_initial_message(vec![r], vec![cdd_id.0], &mut rng).unwrap();

        let challenge = Challenge(Scalar::random(&mut rng).into());
        let cdd_id_proof_response = apply_challenge(&cdd_id_proof_secrets, &challenge);
        assert!(verify(
            &cdd_id_proof,
            &cdd_id_proof_response,
            &statement,
            &challenge,
        ));
    }

    #[test]
    fn non_interactive_zkp() {
        // Prep
        let mut rng = StdRng::from_seed([42u8; 32]);

        let mut investor_did = [0u8; 32];
        rng.fill_bytes(&mut investor_did);
        let mut investor_unique_id = [0u8; 32];
        rng.fill_bytes(&mut investor_unique_id);
        let claim = CddClaimData::new(&investor_did, &investor_unique_id);
        let cdd_id = compute_cdd_id(&claim);
        let r = Scalar::random(&mut rng);
        let statement = cdd_id.0 * r;

        // Prover
        let (initial_message, final_response) =
            non_interactive_prove(vec![r], vec![cdd_id.0], &mut rng).unwrap();

        // Verifier
        assert!(non_interactive_verify(&initial_message, &final_response, &statement).unwrap());
    }
}
