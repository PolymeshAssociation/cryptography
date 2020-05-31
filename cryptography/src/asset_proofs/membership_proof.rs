//! Membership proofs are zero-knowledge proofs systems which enables to efficiently prove
//! that the committed secret belongs to the given set of public elements without
//! revealing any other information about the secret.
//! This implementation is based on one-out-of-many proof construction desribed in the following paper
//! <https://eprint.iacr.org/2015/643.pdf>

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use std::time::Instant;
use crate::asset_proofs::{
    encryption_proofs::{
        AssetProofProver, AssetProofProverAwaitingChallenge, AssetProofVerifier, ZKPChallenge,
    },
    one_out_of_many_proof::{
        OOONProofFinalResponse, OOONProofInitialMessage, OOONProofVerifier, OOONProver,
        OOONProverAwaitingChallenge, OooNProofGenerators, R1ProofVerifier, convert_to_base, 
        convert_to_matrix_rep, R1ProverAwaitingChallenge, Matrix, Polynomial,
    },
    transcript::{TranscriptProtocol, UpdateTranscript},
};
use crate::errors::{ErrorKind, Fallible};
use merlin::{Transcript, TranscriptRng};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MEMBERSHIP_PROOF_LABEL: &[u8] = b"PolymathMembershipProofLabel";
const MEMBERSHIP_PROOF_CHALLENGE_LABEL: &[u8] = b"PolymathMembershipProofChallengeLabel";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct MembershipProofInitialMessage {
    ooon_proof_initial_message: OOONProofInitialMessage,
    secret_element_comm: RistrettoPoint,
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct MembershipProofFinalResponse {
    ooon_proof_final_response: OOONProofFinalResponse,
}

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
    /// Indicates the index of the secret eleent in the elements set.
    pub secret_position: usize,
    /// The element set size is represented as a power of the given base.
    pub base: usize,
    /// Used to specify the commitment list size for the underlying one-out-of-many proofs.
    pub exp: usize,
}

impl<'a> MembershipProverAwaitingChallenge<'a> {
    pub fn new(
        secret_element: Scalar,
        random: Scalar,
        generators: &'a OooNProofGenerators,
        elements_set: &'a [Scalar],
        base: usize,
        exp: usize,
    ) -> Fallible<Self> {
        let secret_position = elements_set.iter().position(|&r| r == secret_element);

        let secret_position =
            secret_position.ok_or_else(|| ErrorKind::MembershipProofInvalidAssetError)?;

        ensure!(elements_set.len() != 0, ErrorKind::EmptyElementsSet);

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
        let exp = self.exp as u32;
        let n = self.base.pow(exp);

        let pc_gens = self.generators.com_gens;

        let secret_commitment = pc_gens.commit(*self.secret_element, *self.random);

        let initial_size = self.elements_set.len();

        let mut commitments_list: Vec<RistrettoPoint> = (0..initial_size)
            .map(|m| secret_commitment - self.elements_set[m] * pc_gens.B)
            .collect();
        
        if n != initial_size {
            commitments_list.resize(n, commitments_list[initial_size - 1]);
        }
        
        let ooon_prover = OOONProverAwaitingChallenge {
            secret_index: self.secret_position,
            random: *self.random,
            generators: self.generators,
            commitments: commitments_list.as_slice(),
            exp: self.exp,
            base: self.base,
        };

        let (ooon_prover, ooon_proof_initial_message) = ooon_prover.generate_initial_message(rng);

        (
            MembershipProver { ooon_prover },
            MembershipProofInitialMessage {
                ooon_proof_initial_message,
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
        ensure!(self.elements_set.len() != 0, ErrorKind::EmptyElementsSet);

        let n = initial_message
            .ooon_proof_initial_message
            .n
            .pow(initial_message.ooon_proof_initial_message.m as u32);
        let initial_size = self.elements_set.len();

        let mut commitments_list: Vec<RistrettoPoint> = (0..self.elements_set.len())
            .map(|m| self.secret_element_com - self.elements_set[m] * self.generators.com_gens.B)
            .collect();

        // If the elements set size does not match to the system parameter N = n^m, we have to
        // pad the resulted commitment list with its last commitment to make the list size equal to N.
        // Padding has a critical security importance.
        if n != initial_size {
            commitments_list.resize(n, commitments_list[initial_size - 1]);
        }

        let ooon_verifier = OOONProofVerifier {
            generators: self.generators,
            commitments: &commitments_list,
        };

        let result = ooon_verifier.verify(
            c,
            &initial_message.ooon_proof_initial_message,
            &final_response.ooon_proof_final_response,
        );
        ensure!(
            result.is_ok(),
            ErrorKind::MembershipProofVerificationError { check: 1 }
        );

        Ok(())
    }
}
impl<'a>  MembershipProverAwaitingChallenge<'a> {
    fn fast_generate_initial_message(
        &self,
        rng: &mut TranscriptRng,
    ) -> (MembershipProver, MembershipProofInitialMessage)
    {
        let exp = self.exp as u32;
        let n = self.base.pow(exp);
        let pc_gens = self.generators.com_gens;

        let secret_commitment = pc_gens.commit(*self.secret_element, *self.random);

        let mut initial_size = self.elements_set.len();
        if initial_size > n {
            initial_size = n;
        }
        let rho: Vec<Scalar> = (0..self.exp).map(|_| Scalar::random(rng)).collect();
        let l_bit_matrix = convert_to_matrix_rep(self.secret_position, self.base, exp).unwrap();

        let b_matrix_rep = Matrix {
            rows: self.exp,
            columns: self.base,
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

        let one = Polynomial::new(self.exp);
        let mut polynomials: Vec<Polynomial> = Vec::with_capacity(n);

        for i in 0..n {
            polynomials.push(one.clone());
            let i_rep = convert_to_base(i, self.base, exp).unwrap();
            for k in 0..self.exp {
                let t = k * self.base + i_rep[k];
                polynomials[i].add_factor(l_bit_matrix[t], r1_prover.a_values[t]);
            }
        }

        let mut sum1 = Scalar::zero();
        let mut sum2 = Scalar::zero();
        let mut G_values: Vec<RistrettoPoint> = Vec::with_capacity(self.exp);
        for k in 0..self.exp {
            G_values.push(rho[k] * pc_gens.B_blinding); 
            for i in 0..n {
                sum1 += polynomials[i].coeffs[k];
                if i < initial_size{
                    sum2 += polynomials[i].coeffs[k] * self.elements_set[i];
                }
                else{
                    sum2 += (self.elements_set[initial_size-1] * polynomials[i].coeffs[k]);
                }
            }
            G_values[k] += (sum1 * secret_commitment) - (sum2 * pc_gens.B);
        }

        let ooon_prover = OOONProver {
                rho_values: rho,
                r1_prover: Zeroizing::new(r1_prover),
                m: self.exp,
                n: self.base,
            };
        let ooon_proof_initial_message = OOONProofInitialMessage {
                r1_proof_initial_message: r1_initial_message,
                g_vec: G_values,
                m: self.exp,
                n: self.base,
            };
    
        (
            MembershipProver { ooon_prover },

            MembershipProofInitialMessage {
                ooon_proof_initial_message,
                secret_element_comm: secret_commitment,
            },
        )
    }
}
impl<'a>  MembershipProofVerifier<'a> {
    /// The verification of one-out-of-many proof is linear from the size of commitment set and
    /// its most computationally heavy part boils down to a big multi-exponentation operation of the form
    /// `p_0 * C_0 + p_1 * C_1 + .... + p_{N-1} * C_{N-1}`. Here the set `{C_0, C_1, ..., C_{N-1}`
    /// is the public list of commitments, and each scalar element `p_i` is computed dynamically
    /// during the verification process. Hence the verification of one-ouf-of-N proof  
    /// requires O(N) computationally heavy scalar mutliplication operations. 
    /// Considering the unique structure of commitments used for membership proofs, we can significanly lower the number of 
    /// required scalar-multiplication operations and perform the verification by 
    /// performing 2N addition operation + 2 scalar multiplication instead. 
    fn fast_verify(
        &self,
        c: &ZKPChallenge,
        initial_message: &MembershipProofInitialMessage,
        final_response: &MembershipProofFinalResponse,
    ) -> Fallible<()> {

        
        let m = final_response.ooon_proof_final_response.m();
        let n = final_response.ooon_proof_final_response.n();

        let size = n.pow(m as u32);
        let mut initial_size = self.elements_set.len();
        if initial_size > size {
            initial_size = size;
        }
        println!("Second check : {} - {}", initial_size, size);

        let b_comm = initial_message.ooon_proof_initial_message.r1_proof_initial_message.b();
        let r1_verifier = R1ProofVerifier {
            b: b_comm,
            generators: self.generators,
        };

        let result_r1 = r1_verifier.verify(
            c,
            &initial_message.ooon_proof_initial_message.r1_proof_initial_message,
            &final_response.ooon_proof_final_response.r1_proof_final_response(),
        );
        ensure!(
            result_r1.is_ok(),
            ErrorKind::MembershipProofVerificationError { check: 1 }
        );

        let mut f_values = vec![*c.x(); m * n];
        let proof_f_elements = &final_response.ooon_proof_final_response.r1_proof_final_response().f_elements();

        for i in 0..m {
            for j in 1..n {
                f_values[(i * n + j)] = proof_f_elements[(i * (n - 1) + (j - 1))];
                f_values[(i * n)] -= proof_f_elements[(i * (n - 1) + (j - 1))];
            }
        }

        let mut p_i: Scalar;
        let mut left: RistrettoPoint = RistrettoPoint::default();
        let right = final_response.ooon_proof_final_response.z() * self.generators.com_gens.B_blinding;

        let mut sum1 = Scalar::zero();
        let mut sum2 = Scalar::zero();

        for i in 0..size {
            p_i = Scalar::one();
            let i_rep = convert_to_base(i, n, m as u32)?;
            for j in 0..m {
                p_i *= f_values[j * n + i_rep[j]];
            }
            sum1 += p_i;
            //sum2 += self.elements_set[i] * p_i;
            if i < initial_size {
                sum2 += self.elements_set[i] * p_i;
            }
            else{
                sum2 += self.elements_set[initial_size-1] * p_i;
            }
        }
        
        left  = sum1 * self.secret_element_com - sum2 * self.generators.com_gens.B;
        
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
    use bincode::{deserialize, serialize};
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    use crate::asset_proofs::encryption_proofs::{
        single_property_prover, single_property_verifier,
    };

    const SEED_1: [u8; 32] = [42u8; 32];
    #[test]
    #[ignore]
    #[wasm_bindgen_test]
    /// Tests the whole workflow of membership proofs
    fn test_membership_proofs() {
        let mut rng = StdRng::from_seed(SEED_1);
        let mut transcript = Transcript::new(MEMBERSHIP_PROOF_LABEL);

        const BASE: usize = 4;
        const EXPONENT: usize = 3;

        let generators = OooNProofGenerators::new(EXPONENT, BASE);

        let even_elements: Vec<Scalar> = (0..64 as u32).map(|m| Scalar::from(2 * m)).collect();
        let odd_elements: Vec<Scalar> = (0..64 as u32).map(|m| Scalar::from(2 * m + 1)).collect();

        let blinding = Scalar::random(&mut rng);

        let even_member = generators.com_gens.commit(Scalar::from(8u32), blinding);
        let odd_member = generators.com_gens.commit(Scalar::from(75u32), blinding);

        let prover = MembershipProverAwaitingChallenge::new(
            Scalar::from(8u32),
            blinding.clone(),
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

        let result = verifier.verify(&challenge, &initial_message.clone(), &final_response.clone());
        assert!(result.is_ok());

        let faster_result = verifier.fast_verify(&challenge, &initial_message.clone(), &final_response.clone());
        assert!(faster_result.is_ok());

        // Negative test
        let verifier = MembershipProofVerifier {
            secret_element_com: odd_member,
            elements_set: even_elements.as_slice(),
            generators: &generators,
        };
        let result = verifier.verify(&challenge, &initial_message, &final_response);
        assert_err!(
            result,
            ErrorKind::MembershipProofVerificationError { check: 1 }
        );

        // Testing the attempt of initializting the prover with ian nvalid asset or an asset list.
        let prover = MembershipProverAwaitingChallenge::new(
            Scalar::from(78953u32),
            blinding.clone(),
            &generators,
            even_elements.as_slice(),
            BASE,
            EXPONENT,
        );
        assert!(prover.is_err());

        // Testing the non-interactive API
        let prover = MembershipProverAwaitingChallenge::new(
            Scalar::from(75u32),
            blinding.clone(),
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
                initial_message_1.clone(),
                final_response_1.clone()
            )
            .is_ok()
        );

        // Negative tests
        let bad_initial_message = initial_message;
        let bad_final_response = final_response;
        assert_err!(
            single_property_verifier(&verifier, bad_initial_message, final_response_1),
            ErrorKind::MembershipProofVerificationError { check: 1 }
        );

        assert_err!(
            single_property_verifier(&verifier, initial_message_1, bad_final_response),
            ErrorKind::MembershipProofVerificationError { check: 1 }
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_membership_proof_fast_proof_generation_verification() {
        let mut rng = StdRng::from_seed(SEED_1);

        const BASE: usize = 4;
        const EXPONENT: usize = 2;
        let N : usize = BASE.pow(EXPONENT as u32);

        let generators = OooNProofGenerators::new(EXPONENT, BASE);
        
        let elements_set: Vec<Scalar> = (0..(15) as u32).map(|m| Scalar::from(m)).collect();
    
        let secret = Scalar::from(8u32);
        let blinding = Scalar::random(&mut rng);

        let secret_commitment = generators.com_gens.commit(secret, blinding);

        let prover = MembershipProverAwaitingChallenge::new(
            secret,
            blinding.clone(),
            &generators,
            elements_set.as_slice(),
            BASE,
            EXPONENT,
        );

        let mut transcript_rng = prover.create_transcript_rng(&mut rng, &transcript);
        
        let proof_step1_start = Instant::now();
        let (prover, initial_message) = prover.fast_generate_initial_message(&mut transcript_rng);
        let proof_step1_duration = proof_step1_start.elapsed();
        
        initial_message.update_transcript(&mut transcript).unwrap();
        let challenge = transcript
            .scalar_challenge(MEMBERSHIP_PROOF_CHALLENGE_LABEL)
            .unwrap();

        let proof_step2_start = Instant::now();    
        let final_response = prover.apply_challenge(&challenge);
        let proof_step2_duration = proof_step2_start.elapsed();

        let verifier = MembershipProofVerifier {
            secret_element_com: secret_commitment,
            elements_set: elements_set.as_slice(),
            generators: &generators,
        };

        let slow_ver_start = Instant::now();
        let result = verifier.verify(&challenge, &initial_message, &final_response);
        let slow_duration = slow_ver_start.elapsed();
        assert!(result.is_ok());

        let fast_ver_start = Instant::now();
        let faster_result = verifier.fast_verify(&challenge, &initial_message, &final_response);
        let fast_duration = fast_ver_start.elapsed();

        println!("\nProof: Initial Message generation time: {:.2?}", proof_step1_duration);
        println!("Proof: Final Response generation time: {:.2?}", proof_step2_duration);
        println!("Slow verification time: {:.2?}", slow_duration);
        println!("Fast verification time: {:.2?}\n\n", fast_duration);
        assert!(faster_result.is_ok());
    }

    #[test]
    #[ignore]
    #[wasm_bindgen_test]
    fn serialize_deserialize_proof() {
        let mut rng = StdRng::from_seed(SEED_1);

        const BASE: usize = 4;
        const EXPONENT: usize = 3;

        let generators = OooNProofGenerators::new(EXPONENT, BASE);
        let even_elements: Vec<Scalar> = (0..64 as u32).map(|m| Scalar::from(2 * m)).collect();
        let blinding = Scalar::random(&mut rng);

        let prover = MembershipProverAwaitingChallenge::new(
            Scalar::from(8u32),
            blinding.clone(),
            &generators,
            even_elements.as_slice(),
            BASE,
            EXPONENT,
        )
        .unwrap();

        let (initial_message0, final_response0) =
            single_property_prover::<StdRng, MembershipProverAwaitingChallenge>(prover, &mut rng)
                .unwrap();

        let initial_message_bytes: Vec<u8> = serialize(&initial_message0).unwrap();
        let final_response_bytes: Vec<u8> = serialize(&final_response0).unwrap();
        let recovered_initial_message: MembershipProofInitialMessage =
            deserialize(&initial_message_bytes).unwrap();
        let recovered_final_response: MembershipProofFinalResponse =
            deserialize(&final_response_bytes).unwrap();
        assert_eq!(recovered_initial_message, initial_message0);
        assert_eq!(recovered_final_response, final_response0);
    }
}
