//! Membership proofs are zero-knowledge proofs systems which enables to efficiently prove
//! that the committed secret belongs to the given set of public elements without
//! revealing any other information about the secret.
//! This implementation is based on one-out-of-many proof construction described in the following paper
//! <https://eprint.iacr.org/2015/643.pdf>

use crate::{
    asset_proofs::{
        encryption_proofs::{
            AssetProofProver, AssetProofProverAwaitingChallenge, AssetProofVerifier, ZKPChallenge,
            ZKProofResponse,
        },
        errors::{ErrorKind, Fallible},
        one_out_of_many_proof::{
            convert_to_base, convert_to_matrix_rep, Matrix, OOONProofFinalResponse,
            OOONProofInitialMessage, OOONProver, OooNProofGenerators, Polynomial, R1ProofVerifier,
            R1ProverAwaitingChallenge,
        },
        transcript::{TranscriptProtocol, UpdateTranscript},
    },
    codec_wrapper::{RistrettoPointDecoder, RistrettoPointEncoder},
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::{Transcript, TranscriptRng};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use codec::{Decode, Encode, Error as CodecError, Input, Output};
use sp_std::{cmp::min, convert::TryFrom, prelude::*};

pub const MEMBERSHIP_PROOF_LABEL: &[u8] = b"PolymathMembershipProofLabel";
const MEMBERSHIP_PROOF_CHALLENGE_LABEL: &[u8] = b"PolymathMembershipProofChallengeLabel";

#[derive(Clone, Debug, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MembershipProofInitialMessage {
    ooon_proof_initial_message: OOONProofInitialMessage,
    secret_element_comm: RistrettoPoint,
    elements_set_size: u32,
}

impl Encode for MembershipProofInitialMessage {
    #[inline]
    fn size_hint(&self) -> usize {
        self.ooon_proof_initial_message.size_hint()
            + RistrettoPointEncoder(&self.secret_element_comm).size_hint()
            + self.elements_set_size.size_hint()
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.ooon_proof_initial_message.encode_to(dest);
        RistrettoPointEncoder(&self.secret_element_comm).encode_to(dest);
        self.elements_set_size.encode_to(dest);
    }
}

impl Decode for MembershipProofInitialMessage {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let ooon_proof_initial_message = <OOONProofInitialMessage>::decode(input)?;
        let secret_element_comm = <RistrettoPointDecoder>::decode(input)?.0;
        let elements_set_size = <u32>::decode(input)?;

        Ok(MembershipProofInitialMessage {
            ooon_proof_initial_message,
            secret_element_comm,
            elements_set_size,
        })
    }
}

impl UpdateTranscript for MembershipProofInitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> Fallible<()> {
        transcript.append_domain_separator(MEMBERSHIP_PROOF_CHALLENGE_LABEL);
        self.ooon_proof_initial_message
            .update_transcript(transcript)?;

        transcript.append_validated_point(b"Comm", &self.secret_element_comm.compress())?;

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Default, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MembershipProofFinalResponse {
    ooon_proof_final_response: OOONProofFinalResponse,
}

/// Holds the non-interactive proofs of membership, equivalent of L_member of MERCAT paper.
pub type MembershipProof =
    ZKProofResponse<MembershipProofInitialMessage, MembershipProofFinalResponse>;

#[derive(Clone, Debug)]
pub struct MembershipProver {
    ooon_prover: OOONProver,
}
/// The prover awaiting challenge will be initialized by the commitment witness data, which is the
/// committed secret and the blinding factor, and will keep a reference to the public set of elements,
/// to which the committed secret provably belongs to.
pub struct MembershipProverAwaitingChallenge<'a> {
    /// The committed secret element.
    pub secret_element: Zeroizing<Scalar>,
    /// The blinding factor used to commit to the secret_message.
    pub random: Zeroizing<Scalar>,
    /// Generator points used to construct one-out-of-many proofs.
    pub generators: &'a OooNProofGenerators,
    /// The set of elements which the committed secret element belongs to.
    pub elements_set: &'a [Scalar],
    /// Indicates the index of the secret element in the elements set.
    pub secret_position: u32,
    /// The element set size is represented as a power of the given base.
    pub base: u32,
    /// Used to specify the commitment list size for the underlying one-out-of-many proofs.
    pub exp: u32,
}

impl<'a> MembershipProverAwaitingChallenge<'a> {
    pub fn new(
        secret_element: Scalar,
        random: Scalar,
        generators: &'a OooNProofGenerators,
        elements_set: &'a [Scalar],
        base: u32,
        exp: u32,
    ) -> Fallible<Self> {
        let secret_position: u32 = elements_set
            .iter()
            .position(|&r| r == secret_element)
            .ok_or(ErrorKind::MembershipProofInvalidAssetError)?
            as u32;

        ensure!(!elements_set.is_empty(), ErrorKind::EmptyElementsSet);

        Ok(MembershipProverAwaitingChallenge {
            secret_element: Zeroizing::new(secret_element),
            random: Zeroizing::new(random),
            generators,
            elements_set,
            secret_position,
            base,
            exp,
        })
    }
}

impl<'a> AssetProofProverAwaitingChallenge for MembershipProverAwaitingChallenge<'a> {
    type ZKInitialMessage = MembershipProofInitialMessage;
    type ZKFinalResponse = MembershipProofFinalResponse;
    type ZKProver = MembershipProver;

    fn create_transcript_rng<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        transcript: &Transcript,
    ) -> TranscriptRng {
        transcript
            .build_rng()
            .rekey_with_witness_bytes(b"secret_element", self.secret_element.as_bytes())
            .rekey_with_witness_bytes(b"random", self.random.as_bytes())
            .finalize(rng)
    }

    /// Given a commitment `C = m*B+r*B_blinding` to a secret element `m`, a membership proof proves that
    /// `m` belongs to the given public set of elements `m_1, m_2, ..., m_N`. Membership proof is comprised
    /// of an one-out-of-many proof generated with respect to an
    /// ad-hoc computed list of commitments. Each commmitment `C_i` in this list is computed by subtracting
    /// the corresponding public set element `m_i` from the user commitment C as follows: `C_i = C - m_i * B`.
    /// If `m` truly belongs to the given set `m_1, m_2, ..., m_N`, then obviously the list of committments
    /// `C_1, C_2, ... C_N` contains a commitment opening to 0.
    fn generate_initial_message(
        &self,
        rng: &mut TranscriptRng,
    ) -> (Self::ZKProver, Self::ZKInitialMessage) {
        let exp = self.exp;
        let size = self.base.pow(exp);
        let pc_gens = self.generators.com_gens;

        let secret_commitment = pc_gens.commit(*self.secret_element, *self.random);

        let initial_size = min(self.elements_set.len() as u32, size);

        let rho: Vec<Scalar> = (0..self.exp).map(|_| Scalar::random(rng)).collect();
        let l_bit_matrix =
            convert_to_matrix_rep(self.secret_position as usize, self.base as usize, exp);

        let b_matrix_rep = Matrix {
            rows: self.exp as usize,
            columns: self.base as usize,
            elements: l_bit_matrix.clone(),
        };

        let r1_prover = R1ProverAwaitingChallenge {
            b_matrix: Zeroizing::new(b_matrix_rep),
            r_b: Zeroizing::new(*self.random),
            generators: self.generators,
            m: self.exp,
            n: self.base,
        };

        let (r1_prover, r1_initial_message) = r1_prover.generate_initial_message(rng);

        let one = Polynomial::new(self.exp as usize);
        let mut polynomials: Vec<Polynomial> = Vec::with_capacity(size as usize);

        for i in 0..size as usize {
            polynomials.push(one.clone());
            let i_rep = convert_to_base(i, self.base as usize, exp);
            for (k, item) in i_rep.iter().enumerate().take(self.exp as usize) {
                let t: usize = k * self.base as usize + item;
                polynomials[i].add_factor(l_bit_matrix[t], r1_prover.a_values[t]);
            }
        }

        let mut g_values: Vec<RistrettoPoint> = Vec::with_capacity(self.exp as usize);
        for k in 0..self.exp as usize {
            g_values.push(rho[k] * pc_gens.B_blinding);
            let mut sum1 = Scalar::zero();
            let mut sum2 = Scalar::zero();
            for (i, polynomial) in polynomials.iter().enumerate().take(initial_size as usize) {
                sum1 += polynomial.coeffs[k];
                sum2 += polynomial.coeffs[k] * self.elements_set[i];
            }
            if size > initial_size {
                for polynomial in polynomials
                    .iter()
                    .take(size as usize)
                    .skip(initial_size as usize)
                {
                    sum1 += polynomial.coeffs[k];
                    sum2 += polynomial.coeffs[k] * self.elements_set[(initial_size - 1) as usize];
                }
            }
            g_values[k] += (sum1 * secret_commitment) - (sum2 * pc_gens.B);
        }

        let ooon_prover = OOONProver {
            rho_values: rho,
            r1_prover: Zeroizing::new(r1_prover),
            m: self.exp,
            n: self.base,
        };
        let ooon_proof_initial_message = OOONProofInitialMessage {
            r1_proof_initial_message: r1_initial_message,
            g_vec: g_values,
            m: self.exp,
            n: self.base,
        };

        (
            MembershipProver { ooon_prover },
            MembershipProofInitialMessage {
                ooon_proof_initial_message,
                elements_set_size: initial_size,
                secret_element_comm: secret_commitment,
            },
        )
    }
}

impl AssetProofProver<MembershipProofFinalResponse> for MembershipProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> MembershipProofFinalResponse {
        let ooon_proof_final_response = self.ooon_prover.apply_challenge(c);

        MembershipProofFinalResponse {
            ooon_proof_final_response,
        }
    }
}

pub struct MembershipProofVerifier<'a> {
    pub secret_element_com: RistrettoPoint,
    pub elements_set: &'a [Scalar],
    pub generators: &'a OooNProofGenerators,
}

impl<'a> AssetProofVerifier for MembershipProofVerifier<'a> {
    type ZKInitialMessage = MembershipProofInitialMessage;
    type ZKFinalResponse = MembershipProofFinalResponse;

    fn verify(
        &self,
        c: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        final_response: &Self::ZKFinalResponse,
    ) -> Fallible<()> {
        let m = initial_message.ooon_proof_initial_message.m as usize;
        let n = initial_message.ooon_proof_initial_message.n as usize;
        let exp = u32::try_from(m).map_err(|_| ErrorKind::InvalidExponentParameter)?;
        let size = initial_message.ooon_proof_initial_message.n.pow(exp) as usize;

        // Use the minimum of the prover and verifier's elements set size.
        // This way if on the verifier side, new elements are appended to the elements
        // set, the proofs made with the old element set will still verify.
        let element_set_size = min(
            initial_message.elements_set_size as usize,
            self.elements_set.len(),
        );

        let initial_size = min(element_set_size, size);
        ensure!(initial_size != 0, ErrorKind::EmptyElementsSet);
        let b_comm = initial_message
            .ooon_proof_initial_message
            .r1_proof_initial_message
            .b();
        let r1_verifier = R1ProofVerifier {
            b: b_comm,
            generators: self.generators,
        };

        r1_verifier
            .verify(
                c,
                &initial_message
                    .ooon_proof_initial_message
                    .r1_proof_initial_message,
                &final_response
                    .ooon_proof_final_response
                    .r1_proof_final_response(),
            )
            .map_err(|_| ErrorKind::MembershipProofVerificationError { check: 1 })?;

        let mut f_values = vec![*c.x(); m * n];
        let proof_f_elements = &final_response
            .ooon_proof_final_response
            .r1_proof_final_response()
            .f_elements();

        for i in 0..m {
            for j in 1..n {
                let proof_f_idx = i * (n - 1) + (j - 1);
                f_values[(i * n + j)] = proof_f_elements[proof_f_idx];
                f_values[(i * n)] -= proof_f_elements[proof_f_idx];
            }
        }

        let mut p_i: Scalar;
        let right =
            final_response.ooon_proof_final_response.z() * self.generators.com_gens.B_blinding;

        let mut sum1 = Scalar::zero();
        let mut sum2 = Scalar::zero();

        // For all given asset identifiers from the list of public asset ids
        // we compute the corresponding elements `p_i` and compute the aggregates
        // sum1` ands `sum2`.
        for i in 0..initial_size {
            p_i = Scalar::one();
            let i_rep = convert_to_base(i, n, m as u32);
            for j in 0..m as usize {
                p_i *= f_values[j * n as usize + i_rep[j]];
            }
            sum1 += p_i;
            sum2 += self.elements_set[i] * p_i;
        }
        // Membership proof require the list of asset ids to have a certain length `size`.
        // In case of the list actual size is smaller than the required size. We should pad the list
        // with the last element until the size of the resulted set will be equal to `size`.
        // This padding operation can be directly incorporated into the computation
        // of the aggregated value `sum2`.

        // The code snippet within the lines 316-321 duplicates the snippet from 299-304 and obviously we
        // could have avoided this by simply checking if `i > initial_size` during the `sum2` aggregation,
        // but that would require making the `if` checks for all `i in initial_size..size`
        // which would be more inefficient approach.

        if size > initial_size {
            let last = self.elements_set[initial_size - 1];
            for i in initial_size..size as usize {
                p_i = Scalar::one();
                let i_rep = convert_to_base(i, n, m as u32);
                for j in 0..m as usize {
                    p_i *= f_values[j * n + i_rep[j]];
                }
                sum1 += p_i;
                sum2 += last * p_i;
            }
        }

        let mut left = sum1 * self.secret_element_com - sum2 * self.generators.com_gens.B;
        let mut temp = Scalar::one();
        for k in 0..m {
            left -= temp * initial_message.ooon_proof_initial_message.g_vec[k];
            temp *= c.x();
        }

        ensure!(
            left == right,
            ErrorKind::MembershipProofVerificationError { check: 2 }
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    extern crate wasm_bindgen_test;
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    use crate::asset_proofs::encryption_proofs::{
        single_property_prover, single_property_verifier,
    };

    const SEED_1: [u8; 32] = [42u8; 32];
    #[test]
    #[wasm_bindgen_test]
    /// Tests the whole workflow of membership proofs
    fn test_membership_proofs() {
        let mut rng = StdRng::from_seed(SEED_1);
        let mut transcript = Transcript::new(MEMBERSHIP_PROOF_LABEL);

        const BASE: u32 = 4;
        const EXPONENT: u32 = 3;

        let generators = OooNProofGenerators::new(EXPONENT, BASE);

        let even_elements: Vec<Scalar> = (0..64 as u32).map(|m| Scalar::from(2 * m)).collect();
        let odd_elements: Vec<Scalar> = (0..64 as u32).map(|m| Scalar::from(2 * m + 1)).collect();

        let blinding = Scalar::random(&mut rng);

        let even_member = generators.com_gens.commit(Scalar::from(8u32), blinding);
        let odd_member = generators.com_gens.commit(Scalar::from(7u32), blinding);

        let prover = MembershipProverAwaitingChallenge::new(
            Scalar::from(8u32),
            blinding,
            &generators,
            even_elements.as_slice(),
            BASE,
            EXPONENT,
        )
        .unwrap();

        let mut transcript_rng = prover.create_transcript_rng(&mut rng, &transcript);
        let (prover, initial_message) = prover.generate_initial_message(&mut transcript_rng);

        initial_message.update_transcript(&mut transcript).unwrap();
        let challenge = transcript
            .scalar_challenge(MEMBERSHIP_PROOF_CHALLENGE_LABEL)
            .unwrap();

        let final_response = prover.apply_challenge(&challenge);

        // Positive test
        let verifier = MembershipProofVerifier {
            secret_element_com: even_member,
            elements_set: even_elements.as_slice(),
            generators: &generators,
        };

        let result = verifier.verify(&challenge, &initial_message, &final_response);
        assert!(result.is_ok());

        // Negative test
        let verifier = MembershipProofVerifier {
            secret_element_com: odd_member,
            elements_set: even_elements.as_slice(),
            generators: &generators,
        };
        let result = verifier.verify(&challenge, &initial_message, &final_response);
        assert_err!(
            result,
            ErrorKind::MembershipProofVerificationError { check: 2 }
        );

        // Testing the attempt of initializting the prover with an invalid asset or an asset list.
        let prover = MembershipProverAwaitingChallenge::new(
            Scalar::from(78953u32),
            blinding,
            &generators,
            even_elements.as_slice(),
            BASE,
            EXPONENT,
        );
        assert!(prover.is_err());

        // Testing the non-interactive API
        let prover = MembershipProverAwaitingChallenge::new(
            Scalar::from(7u32),
            blinding,
            &generators,
            odd_elements.as_slice(),
            BASE,
            EXPONENT,
        )
        .unwrap();

        let verifier = MembershipProofVerifier {
            secret_element_com: odd_member,
            elements_set: odd_elements.as_slice(),
            generators: &generators,
        };

        // 1st to 3rd rounds
        let (initial_message_1, final_response_1) =
            single_property_prover::<StdRng, MembershipProverAwaitingChallenge>(prover, &mut rng)
                .unwrap();

        // Positive test
        assert!(
            // 4th round
            single_property_verifier(
                &verifier,
                (initial_message_1.clone(), final_response_1.clone())
            )
            .is_ok()
        );

        // Negative tests
        let bad_initial_message = initial_message;
        let bad_final_response = final_response;
        assert_err!(
            single_property_verifier(&verifier, (bad_initial_message, final_response_1)),
            ErrorKind::MembershipProofVerificationError { check: 1 }
        );

        assert_err!(
            single_property_verifier(&verifier, (initial_message_1, bad_final_response)),
            ErrorKind::MembershipProofVerificationError { check: 1 }
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_membership_proof_fast_proof_generation_verification() {
        let mut rng = StdRng::from_seed(SEED_1);
        let mut transcript = Transcript::new(MEMBERSHIP_PROOF_LABEL);

        const BASE: u32 = 4;
        const EXPONENT: u32 = 8;

        let generators = OooNProofGenerators::new(EXPONENT, BASE);

        let elements_set: Vec<Scalar> = (0..20000u32).map(Scalar::from).collect();

        let secret = Scalar::from(8760u32);
        let blinding = Scalar::random(&mut rng);

        let secret_commitment = generators.com_gens.commit(secret, blinding);

        let prover = MembershipProverAwaitingChallenge::new(
            secret,
            blinding,
            &generators,
            elements_set.as_slice(),
            BASE,
            EXPONENT,
        )
        .unwrap();

        let mut transcript_rng = prover.create_transcript_rng(&mut rng, &transcript);

        let (prover, initial_message) = prover.generate_initial_message(&mut transcript_rng);

        initial_message.update_transcript(&mut transcript).unwrap();
        let challenge = transcript
            .scalar_challenge(MEMBERSHIP_PROOF_CHALLENGE_LABEL)
            .unwrap();

        let final_response = prover.apply_challenge(&challenge);

        let verifier = MembershipProofVerifier {
            secret_element_com: secret_commitment,
            elements_set: elements_set.as_slice(),
            generators: &generators,
        };

        let result = verifier.verify(&challenge, &initial_message, &final_response);

        assert!(result.is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn serialize_deserialize_proof() {
        let mut rng = StdRng::from_seed(SEED_1);

        const BASE: u32 = 4;
        const EXPONENT: u32 = 3;

        let generators = OooNProofGenerators::new(EXPONENT, BASE);
        let even_elements: Vec<Scalar> = (0..64 as u32).map(|m| Scalar::from(2 * m)).collect();
        let blinding = Scalar::random(&mut rng);

        let prover = MembershipProverAwaitingChallenge::new(
            Scalar::from(8u32),
            blinding,
            &generators,
            even_elements.as_slice(),
            BASE,
            EXPONENT,
        )
        .unwrap();

        let (initial_message0, final_response0) =
            single_property_prover::<StdRng, MembershipProverAwaitingChallenge>(prover, &mut rng)
                .unwrap();

        let bytes = initial_message0.encode();
        let mut input = bytes.as_slice();
        let recovered_initial_message =
            <MembershipProofInitialMessage>::decode(&mut input).unwrap();
        assert_eq!(recovered_initial_message, initial_message0);

        let bytes = final_response0.encode();
        let mut input = bytes.as_slice();
        let recovered_final_response = <MembershipProofFinalResponse>::decode(&mut input).unwrap();
        assert_eq!(recovered_final_response, final_response0);
    }
}
