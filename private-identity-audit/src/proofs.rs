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

use crate::errors::{ErrorKind, Fallible};
use crate::Challenge;
use cryptography_core::curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};

#[derive(Clone)]
pub struct InitialMessage {
    a: RistrettoPoint,
    pub generators: Vec<RistrettoPoint>,
}

#[derive(Clone)]
pub struct FinalResponse {
    s: Vec<Scalar>,
}

#[derive(Clone)]
pub struct Secrets {
    rands: Vec<Scalar>,
    secrets: Vec<Scalar>,
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
        .clone()
        .into_iter()
        .zip(&rands)
        .map(|(gen, rand)| gen * rand)
        .fold_first(|v1, v2| v1 + v2)
        .ok_or(ErrorKind::InitialMessageGenError)?;
    Ok((Secrets { rands, secrets }, InitialMessage { a, generators }))
}

pub fn apply_challenge(prover_secrets: &Secrets, c: Challenge) -> FinalResponse {
    let s = (&prover_secrets.rands)
        .iter()
        .zip(&prover_secrets.secrets)
        .map(|(rand, secret)| rand + c * secret)
        .collect();

    FinalResponse { s }
}

pub fn verify(
    initial_message: InitialMessage,
    final_response: &FinalResponse,
    statement: &RistrettoPoint,
    c: &Challenge,
) -> bool {
    if let Some(lhs) = initial_message
        .generators
        .into_iter()
        .zip(&final_response.s)
        .map(|(gen, s)| gen * s)
        .fold_first(|v1, v2| v1 + v2)
    {
        return lhs == initial_message.a + statement * c;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::generate_blinding_factor;
    use confidential_identity::{pedersen_commitments::PedersenGenerators, CddClaimData};
    use cryptography_core::curve25519_dalek::traits::MultiscalarMul;
    use rand::{rngs::StdRng, SeedableRng};

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

        let c = Scalar::random(&mut rng);
        let final_response = apply_challenge(&prover_secrets, c);

        // Positive test
        assert!(verify(
            initial_message.clone(),
            &final_response.clone(),
            &statement,
            &c
        ));

        // Negative test
        let statement = RistrettoPoint::random(&mut rng) * Scalar::random(&mut rng);
        let is_valid = verify(initial_message, &final_response, &statement, &c);
        assert!(!is_valid);
    }

    #[test]
    fn test_zkp_cdd_id() {
        let mut rng = StdRng::from_seed([42u8; 32]);
        let pg = PedersenGenerators::default();
        let claim = CddClaimData {
            investor_unique_id: Scalar::random(&mut rng),
            investor_did: Scalar::random(&mut rng),
        };
        let blinding_factor =
            generate_blinding_factor(claim.investor_did, claim.investor_unique_id);
        let secrets = [
            claim.investor_did,
            claim.investor_unique_id,
            blinding_factor,
        ];
        let cdd_id = pg.commit(&secrets);
        let r = Scalar::random(&mut rng);
        let statement = cdd_id * r;
        let (cdd_id_proof_secrets, cdd_id_proof) =
            generate_initial_message(vec![r], vec![cdd_id], &mut rng).unwrap();

        let challenge = Scalar::random(&mut rng);
        let cdd_id_proof_response = apply_challenge(&cdd_id_proof_secrets, challenge);
        assert!(verify(
            cdd_id_proof,
            &cdd_id_proof_response,
            &statement,
            &challenge,
        ));
    }
}
