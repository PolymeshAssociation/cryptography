//! One-out-of-many proof is a Sigma protocol enabling to efficiently prove the knowledge
//! of a secret commitment among the public list of N commitments, which is opening to 0.
//! It is important to note that the provided list size should be exactly N=n^m.
//! If the commitment list size is smaller than N, it should be padded with the last commitment.
//! For more details see the original paper https://eprint.iacr.org/2015/643.pdf

#![allow(non_snake_case)]
use bulletproofs::PedersenGens;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_COMPRESSED, constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};

use crate::asset_proofs::{
    encryption_proofs::{
        AssetProofProver, AssetProofProverAwaitingChallenge, AssetProofVerifier, ZKPChallenge,
    },
    errors::{AssetProofError, Result},
    transcript::{TranscriptProtocol, UpdateTranscript},
};

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use sha3::Sha3_512;
use std::ops::{Add, Neg, Sub};
use zeroize::{Zeroize, Zeroizing};
use std::convert::TryFrom;

const OOON_PROOF_LABEL: &[u8; 14] = b"PolymathMERCAT";
const OOON_PROOF_CHALLENGE_LABEL: &[u8] = b"PolymathOOONProofChallengeLabel";
const R1_PROOF_CHALLENGE_LABEL: &[u8] = b"PolymathR1ProofChallengeLabel";

/// One-out-of-Many Proofs are instantiated with a fixed value `N = n^m`,
/// `n` and `m` are system parameters which choice has a significant impact on the final proof sizes and performance.
/// `n` is the fixed base. Usually we will work with base `4`.
/// Returns the representation of the input number as the given base number
/// The input number should be within the provided range [0, base^exp)
fn convert_to_base(number: usize, base: usize, exp: usize) -> Result<Vec<usize>, AssetProofError> {
    ensure!(
        number < base.pow(u32::try_from(exp).unwrap()),
        AssetProofError::OOONProofIndexOutofRange
    );

    let mut rem: usize;
    let mut number = number;
    let mut base_rep = Vec::with_capacity(exp);

    for _j in 0..exp  {
        rem = number % base;
        number /= base;   
        base_rep.push(rem);
    }

    Ok(base_rep)
}
/// Returns a special bit-matrix representation of the input number.
/// The input `number` should be within the provided range `[0, base^exp)`
/// The number is represented as the given base number `n = n0 *base^0 + n1 *base^1 +...+ n_exp *base^{exp-1}`
/// The return value is a bit-matrix of size `exp x base` where
/// in the  `j`-th row there is exactly one 1 at the cell matrix[j][n_j].
fn convert_to_matrix_rep(
    number: usize,
    base: usize,
    exp: usize,
) -> Result<Vec<Scalar>, AssetProofError> {
    ensure!(
        number < base.pow(u32::try_from(exp).unwrap()),
        AssetProofError::OOONProofIndexOutofRange
    );

    let mut rem: usize;
    let mut number = number;
    let mut matrix_rep = vec![Scalar::zero(); exp * base];
    for j in 0..exp {
        rem = number % base;
        number /= base;
        matrix_rep[j * base + rem] = Scalar::one();
    }

    Ok(matrix_rep)
}

/// Generates `n * m + 2` group generators exploited by the one-out-of-many proof algorithm. The later  
/// uses vector commitments of size `n * m` and regular Pedersen commitments.
pub struct OooNProofGenerators {
    /// Generates for computing Pedersen commitments
    com_gens: PedersenGens,
    /// Generators for computing vector commitments.
    h_vec: Vec<RistrettoPoint>,
}

impl OooNProofGenerators {
    pub fn new(base: usize, exp: usize) -> Self {
        let mut generators: Vec<RistrettoPoint> = Vec::with_capacity(exp * base);

        let mut ristretto_base_bytes = Vec::with_capacity(
            OOON_PROOF_LABEL.len() + RISTRETTO_BASEPOINT_COMPRESSED.as_bytes().len(),
        );

        ristretto_base_bytes.extend_from_slice(&OOON_PROOF_LABEL.to_vec());
        ristretto_base_bytes.extend_from_slice(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());

        for i in 0..exp * base {
            generators.push(RistrettoPoint::hash_from_bytes::<Sha3_512>(
                ristretto_base_bytes.as_slice(),
            ));
            ristretto_base_bytes = generators[i].compress().as_bytes().to_vec();
        }

        OooNProofGenerators {
            com_gens: PedersenGens::default(),
            h_vec: generators,
        }
    }

    /// Commits to the given vector by using the provided blinding randomness.
    pub fn vector_commit(
        &self,
        m_vec: &Vec<Scalar>,
        blinding: Scalar,
    ) -> Result<RistrettoPoint, AssetProofError> {
        ensure!(
            &m_vec.len() == &self.h_vec.len(),
            AssetProofError::OOONProofWrongSize
        );

        let commitment: RistrettoPoint = RistrettoPoint::multiscalar_mul(m_vec, &self.h_vec);

        Ok(commitment + (blinding * self.com_gens.B_blinding))
    }
}

impl Default for OooNProofGenerators {
    fn default() -> Self {
        Self::new(4, 3)
    }
}

#[derive(Clone, Debug, PartialEq, Zeroize)]
/// Implements basic Matrix functionality over scalars.
/// The matrix elements are represented through a vector of size row * columns,
/// where `vec[i * columns + j] := matrix[i][j]`
/// Matrix entry-wise multiplications, addition and subtraction operations are used
/// during OOON Proof generation process.
pub struct Matrix {
    elements: Vec<Scalar>,
    rows: usize,
    columns: usize,
}

impl Matrix {
    /// Initializes a new matrix of the given sizes and fills it with the provided default value.
    fn new(r: usize, c: usize, default: Scalar) -> Self {
        Matrix {
            rows: r,
            columns: c,
            elements: vec![default; r * c],
        }
    }
    /// Computes the entry-wise (Hadamard) product of two matrixes of the same dimensions.
    fn entrywise_product(&self, right: &Matrix) -> Result<Matrix, AssetProofError> {
        ensure!(self.rows == right.rows, AssetProofError::OOONProofWrongSize);
        ensure!(
            self.columns == right.columns,
            AssetProofError::OOONProofWrongSize
        );

        let mut entrywise_product: Matrix = Matrix::new(self.rows, right.columns, Scalar::zero());
        for i in 0..self.rows {
            for j in 0..self.columns {
                let k: usize = i * self.columns + j;
                entrywise_product.elements[k] = self.elements[k] * right.elements[k];
            }
        }

        Ok(entrywise_product)
    }
}

impl Neg for Matrix {
    type Output = Matrix;

    fn neg(self) -> Matrix {
        let mut negated: Matrix = Matrix::new(self.rows, self.columns, Scalar::zero());
        for i in 0..self.rows {
            for j in 0..self.columns {
                let k: usize = i * self.columns + j;
                negated.elements[k] = -self.elements[k];
            }
        }

        negated
    }
}
impl<'a, 'b> Add<&'b Matrix> for &'a Matrix {
    type Output = Matrix;
    fn add(self, right: &'b Matrix) -> Matrix {
        assert_eq!(self.rows, right.rows);
        assert_eq!(self.columns, right.columns);

        let mut sum: Matrix = Matrix::new(self.rows, self.columns, Scalar::zero());
        for i in 0..self.rows {
            for j in 0..self.columns {
                let k = i * self.columns + j;
                sum.elements[k] = &self.elements[k] + &right.elements[k];
            }
        }

        sum
    }
}

impl<'a, 'b> Sub<&'b Matrix> for &'a Matrix {
    type Output = Matrix;
    fn sub(self, right: &'b Matrix) -> Matrix {
        assert_eq!(self.rows, right.rows);
        assert_eq!(self.columns, right.columns);

        let mut sub: Matrix = Matrix::new(self.rows, self.columns, Scalar::zero());
        for i in 0..self.rows {
            for j in 0..self.columns {
                let k = i * self.columns + j;
                sub.elements[k] = &self.elements[k] - &right.elements[k];
            }
        }
        sub
    }
}

#[derive(Clone, Debug, PartialEq)]

/// Implements a basic polynomial functionality over scalars
/// The Polynomial struct explicitly stores its degree and the coefficients vector.
/// The first element of the coefficients vector coeffs[0] is the polynomial's free term
/// The coeffs[degree] is the leading coefficient of the polynomial.
pub struct Polynomial {
    degree: usize,
    coeffs: Vec<Scalar>,
}

impl Polynomial {
    /// Takes as parameter the expected degree of the polynomial
    /// to reserve enough capacity for the coefficient vector.
    /// A vector of size degree + 1 is reserved for storing the polynomial's coefficients.
    fn new(expected_degree: usize) -> Polynomial {
        let mut vec = vec![Scalar::zero(); expected_degree + 1];
        vec[0] = Scalar::one();
        Polynomial {
            degree: 0,
            coeffs: vec,
        }
    }

    /// Multipleis the given polynomial `P(x)` with the provided linear `(a * x + b)`.
    fn add_factor(&mut self, a: Scalar, b: Scalar) -> &Polynomial {
        let old = self.coeffs.clone();
        let old_degree = self.degree;

        if a != Scalar::zero() {
            self.degree = self.degree + 1;

            if self.coeffs.len() < self.degree + 1 {
                self.coeffs.resize(self.degree + 1, Scalar::zero());
            }

            self.coeffs[self.degree] = a * old[self.degree - 1];
        }
        for k in 1..=old_degree {
            self.coeffs[k] = b * old[k] + a * old[k - 1];
        }
        self.coeffs[0] = b * old[0];

        self
    }
    /// Computes the polynomial evaluation value at the given point `x`.
    /// Used for testing purposes.
    fn eval(&self, point: Scalar) -> Scalar {
        let mut value = Scalar::zero();
        let mut x: Scalar = Scalar::one();

        for i in 0..=self.degree {
            value += self.coeffs[i] * x;
            x *= point;
        }

        value
    }
}

/// The R1 Proof is a zero-knowledge proof for a (bit-matrix) commitment B having an opening
/// to a bit-matrix, where in each row there is exactly one 1.

#[derive(Copy, Clone, Debug)]
pub struct R1ProofInitialMessage {
    a: RistrettoPoint,
    b: RistrettoPoint,
    c: RistrettoPoint,
    d: RistrettoPoint,
}

impl Default for R1ProofInitialMessage {
    fn default() -> Self {
        R1ProofInitialMessage {
            a: RISTRETTO_BASEPOINT_POINT,
            b: RISTRETTO_BASEPOINT_POINT,
            c: RISTRETTO_BASEPOINT_POINT,
            d: RISTRETTO_BASEPOINT_POINT,
        }
    }
}

impl UpdateTranscript for R1ProofInitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> Result<()> {
        transcript.append_domain_separator(R1_PROOF_CHALLENGE_LABEL);
        transcript.append_validated_point(b"A", &self.a.compress())?;
        transcript.append_validated_point(b"B", &self.b.compress())?;
        transcript.append_validated_point(b"C", &self.c.compress())?;
        transcript.append_validated_point(b"D", &self.d.compress())?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct R1ProofFinalResponse {
    f_elements: Vec<Scalar>,
    z_a: Scalar,
    z_c: Scalar,
    m: usize,
    n: usize,
}

#[derive(Clone, Debug, Zeroize)]
pub struct R1Prover {
    a_values: Vec<Scalar>,
    b_matrix: Zeroizing<Matrix>,
    r_a: Scalar,
    r_b: Scalar,
    r_c: Scalar,
    r_d: Scalar,
    m: usize,
    n: usize,
}
#[derive(Clone, Debug, Zeroize)]
pub struct R1ProverAwaitingChallenge {
    /// The bit-value matrix, where each row contains only one 1
    b_matrix: Matrix,
    /// The randomness used for committing to the bit matrix
    r_b: Scalar,
    m: usize,
    n: usize,
}

impl R1ProverAwaitingChallenge {
    pub fn new(bit_matrix: Matrix, random: Scalar, rows: usize, columns: usize) -> Self {
        R1ProverAwaitingChallenge {
            b_matrix: bit_matrix,
            r_b: random,
            m: rows,
            n: columns,
        }
    }
}

impl AssetProofProverAwaitingChallenge for R1ProverAwaitingChallenge {
    type ZKInitialMessage = R1ProofInitialMessage;
    type ZKFinalResponse = R1ProofFinalResponse;
    type ZKProver = R1Prover;

    fn generate_initial_message<T: RngCore + CryptoRng>(
        &self,
        _p_gens: &PedersenGens,
        rng: &mut T,
    ) -> (Self::ZKProver, Self::ZKInitialMessage) {
        let rows = self.b_matrix.rows;
        let columns = self.b_matrix.columns;
        let generators = OooNProofGenerators::new(rows, columns);

        let random_a = Scalar::random(rng);
        let random_c = Scalar::random(rng);
        let random_d = Scalar::random(rng);

        let ONE = Matrix::new(rows, columns, Scalar::one());
        let TWO = Matrix::new(rows, columns, Scalar::one() + Scalar::one());

        let mut a_matrix = Matrix {
            rows: rows,
            columns: columns,
            elements: (0..(rows * columns)).map(|_| Scalar::random(rng)).collect(),
        };

        for r in 0..a_matrix.rows {
            // The first element of each row is the negated sum of the row's other elements.
            let sum = a_matrix.elements[r * a_matrix.columns + 1..(r + 1) * a_matrix.columns]
                .iter()
                .fold(Scalar::zero(), |s, x| s + x);
            a_matrix.elements[r * a_matrix.columns] = -sum;
        }

        let c_matrix: Matrix = a_matrix
            .clone()
            .entrywise_product(&(&ONE - &TWO.entrywise_product(&self.b_matrix).unwrap()))
            .unwrap();
        let d_matrix: Matrix = -(a_matrix.clone().entrywise_product(&a_matrix).unwrap()); // Implement an associated function taking two matrix parameters
        (
            R1Prover {
                a_values: a_matrix.elements.clone(),
                b_matrix: Zeroizing::new(self.b_matrix.clone()),
                r_b: self.r_b.clone(),
                r_a: random_a,
                r_c: random_c,
                r_d: random_d,
                m: rows,
                n: columns,
            },
            R1ProofInitialMessage {
                a: generators
                    .vector_commit(&a_matrix.elements, random_a)
                    .unwrap(),
                b: generators
                    .vector_commit(&self.b_matrix.elements, self.r_b)
                    .unwrap(),
                c: generators
                    .vector_commit(&c_matrix.elements, random_c)
                    .unwrap(),
                d: generators
                    .vector_commit(&d_matrix.elements, random_d)
                    .unwrap(),
            },
        )
    }
}

impl AssetProofProver<R1ProofFinalResponse> for R1Prover {
    fn apply_challenge(&self, c: &ZKPChallenge) -> R1ProofFinalResponse {
        let mut f_values: Vec<Scalar> = Vec::with_capacity((self.m * (self.n - 1)) as usize);
        for i in 0..self.m {
            for j in 0..(self.n - 1) {
                f_values.push(
                    self.b_matrix.elements[i * self.n + j + 1] * c.x()
                        + self.a_values[i * self.n + j + 1],
                );
            }
        }

        R1ProofFinalResponse {
            f_elements: f_values,
            z_a: self.r_a + c.x() * self.r_b,
            z_c: self.r_d + c.x() * self.r_c,
            m: self.m,
            n: self.n,
        }
    }
}

pub struct R1ProofVerifier {
    b: RistrettoPoint,
}

impl R1ProofVerifier {
    pub fn new(bit_commitment: RistrettoPoint) -> Self {
        R1ProofVerifier { b: bit_commitment }
    }
}

impl AssetProofVerifier for R1ProofVerifier {
    type ZKInitialMessage = R1ProofInitialMessage;
    type ZKFinalResponse = R1ProofFinalResponse;

    fn verify(
        &self,
        _pc_gens: &PedersenGens,
        c: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        final_response: &Self::ZKFinalResponse,
    ) -> Result<()> {
        let rows = final_response.m;
        let columns = final_response.n;

        let mut f_matrix = Matrix::new(rows, columns, *c.x());
        let x_matrix = Matrix::new(rows, columns, *c.x());

        let generators = OooNProofGenerators::new(rows, columns);
        // Here we f[j][0] = x - (f[j][1]+ ... + f[j][columns - 1])
        for i in 0..rows {
            for j in 1..columns {
                f_matrix.elements[i * columns + j] =
                    final_response.f_elements[i * (columns - 1) + (j - 1)];
                f_matrix.elements[i * columns] -=
                    &final_response.f_elements[i * (columns - 1) + (j - 1)];
            }
        }

        let com_f = generators
            .vector_commit(&f_matrix.elements, final_response.z_a)
            .unwrap();
        let com_fx = generators
            .vector_commit(
                &f_matrix
                    .entrywise_product(&(&x_matrix - &f_matrix))
                    .unwrap()
                    .elements,
                final_response.z_c,
            )
            .unwrap();

        ensure!(
            c.x() * self.b + initial_message.a == com_f,
            AssetProofError::R1FinalResponseVerificationError { check: 1 }
        );

        ensure!(
            c.x() * initial_message.c + initial_message.d == com_fx,
            AssetProofError::R1FinalResponseVerificationError { check: 2 }
        );

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct OOONProofInitialMessage {
    r1_proof_initial_message: R1ProofInitialMessage,
    g_vec: Vec<RistrettoPoint>,
    n: usize,
    m: usize,
}

impl OOONProofInitialMessage {
    fn new(base: usize, exp: usize) -> Self {
        OOONProofInitialMessage {
            r1_proof_initial_message: R1ProofInitialMessage::default(),
            g_vec: Vec::with_capacity(exp),
            n: base,
            m: exp,
        }
    }
}
/// A `default` implementation used for testing.
impl Default for OOONProofInitialMessage {
    fn default() -> Self {
        OOONProofInitialMessage::new(4, 3) // TODO: Replace these constants with system-wide parameters for the BASE and EXPONENT
    }
}

impl UpdateTranscript for OOONProofInitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> Result<()> {
        transcript.append_domain_separator(OOON_PROOF_CHALLENGE_LABEL);
        self.r1_proof_initial_message
            .update_transcript(transcript)?;
        for k in 0..self.m  {
            transcript.append_validated_point(b"Gk", &self.g_vec[k].compress())?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct OOONProofFinalResponse {
    r1_proof_final_response: R1ProofFinalResponse,
    z: Scalar,
    m: usize,
    n: usize,
}
#[derive(Clone, Debug, Zeroize)]
pub struct OOONProver {
    rho_values: Vec<Scalar>,
    r1_prover: Zeroizing<R1Prover>,
    m: usize,
    n: usize,
}

/// Given the public list of commitments `C_0, C_1, ..., C_{N-1} where N = base^exp, the prover wants to
/// prove the knowledge of a secret commitment C_l  which is opening to 0.
/// The prover witness is comprised of the secret_index `l` and the commitment's random factor `random`
pub struct OOONProverAwaitingChallenge {
    /// The index of the secret commitment in the given list, which is opening to zero and is blinded by "random"
    secret_index: usize,
    /// The randomness used in the commitment C_{secret_index}
    random: Scalar,
    // The list of N commitments where one commitment is opening to 0. (#TODO Find a way to avoid of cloning this huge data set)
    commitments: Vec<RistrettoPoint>,
    base: usize,
    exp: usize,
}

impl OOONProverAwaitingChallenge {
    pub fn new(
        l: usize,
        r: Scalar,
        commitments_ref: Vec<RistrettoPoint>,
        m: usize,
        n: usize,
    ) -> Self {
        OOONProverAwaitingChallenge {
            secret_index: l,
            random: r,
            commitments: commitments_ref,
            exp: m,
            base: n,
        }
    }
}

impl AssetProofProverAwaitingChallenge for OOONProverAwaitingChallenge {
    type ZKInitialMessage = OOONProofInitialMessage;
    type ZKFinalResponse = OOONProofFinalResponse;
    type ZKProver = OOONProver;

    /// We require the actual size of commitments list to be equal exactly to N = n^m
    /// If the commitment vector size is smaller than N, it should be padded with the last element to make the final commitment vector of size N.
    /// We assume the list is padded already before being passed to the OOON proof initialization process.
    /// This has critical security importance, as non-padded list will open doors for serious privacy issues.
    fn generate_initial_message<T: RngCore + CryptoRng>(
        &self,
        pc_gens: &PedersenGens,
        rng: &mut T,
    ) -> (Self::ZKProver, Self::ZKInitialMessage) {
        let columns = self.base;
        let rows = self.exp;
        let n = self.base.pow(self.exp as u32) ;
        let generators = OooNProofGenerators::new(rows, columns);

        assert_eq!(n, self.commitments.len());

        let rho: Vec<Scalar> = (0..self.exp).map(|_| Scalar::random(rng)).collect();

        let l_bit_matrix = convert_to_matrix_rep(self.secret_index, self.base, self.exp).unwrap();

        let b_matrix_rep = Matrix {
            rows: rows,
            columns: columns,
            elements: l_bit_matrix.clone(),
        };

        let r1_prover = R1ProverAwaitingChallenge::new(b_matrix_rep, self.random, rows, columns);

        let (r1_prover, r1_initial_message) = r1_prover.generate_initial_message(pc_gens, rng);

        let one = Polynomial::new(self.exp );
        let mut polynomials: Vec<Polynomial> = Vec::with_capacity(n);

        for i in 0..n {
            polynomials.push(one.clone());
            let i_rep = convert_to_base(i, self.base, self.exp).unwrap();
            for k in 0..self.exp  {
                let t = k * self.base + i_rep[k];
                polynomials[i].add_factor(l_bit_matrix[t], r1_prover.a_values[t]);
            }
        }

        let mut G_values: Vec<RistrettoPoint> = Vec::with_capacity(self.exp);
        for k in 0..self.exp {
            G_values.push(rho[k] * generators.com_gens.B_blinding); // #TODO: Double check if this matches the El-Gamal generators.
            for i in 0..n {
                G_values[k] += (polynomials[i].coeffs[k]) * self.commitments[i];
            }
        }

        (
            OOONProver {
                rho_values: rho,
                r1_prover: Zeroizing::new(r1_prover),
                m: self.exp,
                n: self.base,
            },
            OOONProofInitialMessage {
                r1_proof_initial_message: r1_initial_message,
                g_vec: G_values,
                m: self.exp,
                n: self.base,
            },
        )
    }
}

impl AssetProofProver<OOONProofFinalResponse> for OOONProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> OOONProofFinalResponse {
        let r1_final_response = self.r1_prover.apply_challenge(c);

        let mut y = Scalar::one();
        let mut z = Scalar::zero();

        for k in 0..self.m  {
            z -= y * self.rho_values[k];
            y *= c.x();
        }

        z += self.r1_prover.r_b * y;

        OOONProofFinalResponse {
            r1_proof_final_response: r1_final_response,
            z: z,
            m: self.m,
            n: self.n,
        }
    }
}

pub struct OOONProofVerifier {
    commitment_list: Vec<RistrettoPoint>,
}

impl OOONProofVerifier {
    pub fn new(list: Vec<RistrettoPoint>) -> Self {
        OOONProofVerifier {
            commitment_list: list,
        }
    }
}

impl AssetProofVerifier for OOONProofVerifier {
    type ZKInitialMessage = OOONProofInitialMessage;
    type ZKFinalResponse = OOONProofFinalResponse;

    fn verify(
        &self,
        pc_gens: &PedersenGens,
        c: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        final_response: &Self::ZKFinalResponse,
    ) -> Result<()> {
        let size = final_response.n.pow(final_response.m as u32);
        let m = final_response.m;
        let n = final_response.n;
        let generators = OooNProofGenerators::new(final_response.m, final_response.n);

        let b_comm = initial_message.r1_proof_initial_message.b;
        let r1_verifier = R1ProofVerifier::new(b_comm);

        let result_r1 = r1_verifier.verify(
            pc_gens,
            c,
            &initial_message.r1_proof_initial_message,
            &final_response.r1_proof_final_response,
        );
        ensure!(
            result_r1.is_ok(),
            AssetProofError::OOONFinalResponseVerificationError { check: 1 }
        );

        let mut f_values = vec![*c.x(); m * n];
        let proof_f_elements = &final_response.r1_proof_final_response.f_elements;

        for i in 0..m {
            for j in 1..n {
                f_values[(i * n + j)] = proof_f_elements[(i * (n - 1) + (j - 1))];
                f_values[(i * n)] -= proof_f_elements[(i * (n - 1) + (j - 1))];
            }
        }

        let mut p_i: Scalar;
        let mut left: RistrettoPoint = RistrettoPoint::default();
        let right = final_response.z * generators.com_gens.B_blinding;

        for i in 0..size {
            p_i = Scalar::one();
            let i_rep = convert_to_base(i, n, m).unwrap();
            for j in 0..m {
                p_i *= f_values[j * n + i_rep[j]];
            }
            left += p_i * self.commitment_list[i];
        }
        let mut temp = Scalar::one();
        for k in 0..m {
            left -= temp * initial_message.g_vec[k];
            temp *= c.x();
        }

        ensure!(
            left == right,
            AssetProofError::OOONFinalResponseVerificationError { check: 2 }
        );

        Ok(())
    }
}

// End of new OOON code

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [42u8; 32];

    #[test]
    #[wasm_bindgen_test]
    /// Tests the whole workflow of one-out-of-many proofs by setting up the parameters base = 4 and exp =3.
    /// This parameters enable to generate 1-out-of-64 proofs which means the prover can prove the knowledge of
    /// one commitment among the public list of 64 commitments, which is opening to 0. The prover does this
    /// without revealing the secret commitment index or its random factor.

    fn test_ooon_proof_api() {
        let pc_gens = PedersenGens::default();
        let mut rng = StdRng::from_seed(SEED_1);

        let mut transcript = Transcript::new(OOON_PROOF_LABEL);

        // Setup the system parameters for base and exponent.
        // This test enables to create 1-out-of-64 proofs.
        const BASE: usize = 4; //n = 3 : COLUMNS
        const EXPONENT: usize = 3; //m = 2 : ROWS
        let generators = OooNProofGenerators::new(EXPONENT, BASE);

        let n = 64;
        let size: usize = 64;

        // Computes the secret commitment which will be opening to 0:
        // `C_secret = 0 * pc_gens.B + r_b * pc_gens.B_Blinding`
        let r_b = Scalar::random(&mut rng);
        let C_secret = r_b * generators.com_gens.B_blinding;

        // Compose a vector of 64 = 4^3 random commitments.
        // This is the global, public list of commitments where we want to prove the knowledge of
        // one commitment opening to 0 without revealing its index or random factor.

        let mut commitments: Vec<RistrettoPoint> = (0..n)
            .map(|_| {
                Scalar::random(&mut rng) * generators.com_gens.B
                    + Scalar::random(&mut rng) * generators.com_gens.B_blinding
            })
            .collect();

        // For different indexes `l`, we set the vec[l] to be our secret commitment `C_secret`.
        // We prove the knowledge of `l` and `r_b` so the commitment vec[l] will be opening to 0.
        for l in 5..size  {
            commitments[l] = C_secret;

            let prover =
                OOONProverAwaitingChallenge::new(l, r_b, commitments.clone(), EXPONENT, BASE);

            let verifier = OOONProofVerifier::new(commitments.clone());
            let (prover, initial_message) = prover.generate_initial_message(&pc_gens, &mut rng);

            initial_message.update_transcript(&mut transcript).unwrap();
            let challenge = transcript
                .scalar_challenge(OOON_PROOF_CHALLENGE_LABEL)
                .unwrap();

            let final_response = prover.apply_challenge(&challenge);

            let result = verifier.verify(&pc_gens, &challenge, &initial_message, &final_response);
            assert!(result.is_ok());
        }
    }

    #[test]
    #[wasm_bindgen_test]
    /// Tests the R1 proof workflow.
    /// Generates a special bit-matrix represenation of the given number, and
    /// each row of the resulted matrix will contain exactly one 1.
    /// Commits to the bit-matrix and proves its "well-formedness" in a zero-knowledge way
    /// with help of R1 proofs.

    fn test_r1_proof_api() {
        let pc_gens = PedersenGens::default();
        let mut rng = StdRng::from_seed(SEED_1);

        let mut transcript = Transcript::new(OOON_PROOF_LABEL);

        const BASE: usize = 4; //n = 3 : COLUMNS
        const EXPONENT: usize = 3; //m = 2 : ROWS
        let generators = OooNProofGenerators::new(EXPONENT, BASE);

        let mut base_matrix: Vec<Scalar>;
        let mut b: Matrix;
        for i in 10..64 {
            base_matrix = convert_to_matrix_rep(i, BASE, EXPONENT).unwrap();

            b = Matrix {
                rows: EXPONENT,
                columns: BASE,
                elements: base_matrix.clone(),
            };
            let r = Scalar::from(45728u32);
            let b_comm = generators.vector_commit(&base_matrix, r).unwrap();
            let prover = R1ProverAwaitingChallenge::new(b, r, EXPONENT, BASE);

            let verifier = R1ProofVerifier::new(b_comm);
            let (prover, initial_message) = prover.generate_initial_message(&pc_gens, &mut rng);

            initial_message.update_transcript(&mut transcript).unwrap();

            let challenge = transcript
                .scalar_challenge(OOON_PROOF_CHALLENGE_LABEL)
                .unwrap();

            let final_response = prover.apply_challenge(&challenge);

            let result = verifier.verify(&pc_gens, &challenge, &initial_message, &final_response);

            assert!(result.is_ok());
        }
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_polynomials() {
        let mut p = Polynomial::new(6);

        p.add_factor(Scalar::from(5u32), Scalar::from(7u32));
        p.add_factor(Scalar::from(5u32), Scalar::from(7u32));
        p.add_factor(Scalar::from(5u32), Scalar::from(7u32));
        p.add_factor(Scalar::from(5u32), Scalar::from(7u32));
        p.add_factor(Scalar::from(5u32), Scalar::from(7u32));
        p.add_factor(Scalar::from(5u32), Scalar::from(7u32));
        let v = p.eval(Scalar::from(8u32));
        assert_eq!(v, Scalar::from(10779215329u64));
    }
}
