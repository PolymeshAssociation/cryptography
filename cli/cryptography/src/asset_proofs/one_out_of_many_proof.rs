// One-out-of-many proof is a Sigma protocol enabling to efficiently prove the knowledge
// of a secret commitment among the public list of N commitments which is opening to 0
#![allow(non_snake_case)]
use bulletproofs::PedersenGens;
use curve25519_dalek::{ristretto::{RistrettoPoint},constants::RISTRETTO_BASEPOINT_COMPRESSED, traits::MultiscalarMul, constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
//use serde::{Serialize, Deserialize};

use crate::asset_proofs::{
        encryption_proofs::{
            AssetProofProver, AssetProofProverAwaitingChallenge, AssetProofVerifier, ZKPChallenge,
        },
        errors::{AssetProofError, Result},
        transcript::{TranscriptProtocol, UpdateTranscript},

    };


use sha3::Sha3_512;
use std::ops::{Add, Sub, Mul, Neg};
use std::convert::TryInto;
use rand::{rngs::StdRng, SeedableRng};
use rand_core::{CryptoRng, RngCore};
const SEED_1: [u8; 32] = [42u8; 32];

use std::time::SystemTime;
use merlin::Transcript;
//use crate::transcript::TranscriptProtocol;
//use crate::matrix::Matrix;


const BASE : u32 = 3;
const EXPONENT : u32 = 2;
const OOON_PROOF_LABEL : &[u8;14] = b"PolymathMERCAT";
const OOON_PROOF_CHALLENGE_LABEL : &[u8] = b"PolymathOOONProofChallengeLabel";
const R1_PROOF_CHALLENGE_LABEL : &[u8] = b"PolymathR1ProofChallengeLabel";


// This utility function is developed for  testing purposes.
pub fn slice_sum(s: &[Scalar]) ->Scalar{
        let mut sum: Scalar = Scalar::zero();
        for i in 0..s.len(){
                sum +=s[i];
        }
        sum
}

pub fn convert_to_matrix_rep(number: u32, base: u32, exp : u32) -> Vec<Scalar> {
        assert!(number < base.pow(exp));
        assert!(number >= 0);

        let mut rem : u32;
        let mut number = number;
        let mut matrix_rep = vec![Scalar::zero(); (exp * base) as usize];
        for j in 0..exp {
                rem = number % base;
                number /= base;
                matrix_rep[(j * base + rem) as usize] = Scalar::one();
        }

        matrix_rep
}

// This function returns the representation of the given number as the given base number
// The given number should be withing the provided range [0, base^exp)

pub fn convert_to_base(number: u32, base: u32, exp : u32) -> Vec<u32> {
        assert!(number < base.pow(exp));
        assert!(number >= 0);

        let mut rem : u32;
        let mut number = number;
        let mut base_rep = vec![0u32; exp as usize];
        for j in 0..exp  as usize{
                rem = number % base;
                number /= base;
                base_rep[j] = rem;
        }


        base_rep
}

// For the given base n and the exponent value m , we need 2 + n * m orthogonal generator points.
// The first two generators are used for Pedersen commitments and are fixed across the cryptography crate.
pub struct OooNProofGenerators {
        // Replace the generators g and h with bulletproof::PedersenGens
        com_gens : PedersenGens,
        h_vec : Vec<RistrettoPoint>

}

impl OooNProofGenerators{
        pub fn new(base:u32, exp:u32) -> Self {
                let mut generators : Vec<RistrettoPoint> = Vec::with_capacity((exp*base) as usize);

                //creating a base array to feed the generator generation process
                let mut ristretto_base_bytes = Vec::with_capacity(
                        OOON_PROOF_LABEL.len() + RISTRETTO_BASEPOINT_COMPRESSED.as_bytes().len(),
                        );

                ristretto_base_bytes.extend_from_slice(&OOON_PROOF_LABEL.to_vec());
                ristretto_base_bytes.extend_from_slice(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());

                for i in 0..exp*base {
                        generators.push(RistrettoPoint::hash_from_bytes::<Sha3_512>(ristretto_base_bytes.as_slice()));
                        ristretto_base_bytes = generators[i as usize].compress().as_bytes().to_vec();

                }


                OooNProofGenerators {
                        com_gens : PedersenGens::default(),
                        h_vec: generators,
                }

        }

        // This function commits to the given message vector by using the provided blinding randomness.
        // The generator point "g" is used for the blinding factor.
        pub fn vector_commit(&self, m_vec: &Vec<Scalar>, blinding: Scalar)-> RistrettoPoint{
                assert_eq!(&m_vec.len(), &self.h_vec.len());
                let commitment: RistrettoPoint = RistrettoPoint::multiscalar_mul(m_vec, &self.h_vec);

                commitment + (blinding * self.com_gens.B_blinding)
        }

        pub fn print_generators(&self) {
                let size = self.h_vec.len();
                for i in 0..size {
                        println!("The {}-th generator point is : {:?}", i, self.h_vec[i].compress().as_bytes());
                }
        }
}

impl Default for OooNProofGenerators {
        fn default() -> Self {
                Self::new(BASE, EXPONENT)
        }
}

// Basic matrix operations over the Scalar field such are matrix addition, multiplication with
// constant and inner-product computations are used for one-out-of-many proof generation.
// Matrixes are represented through vectors. The matrix of size M x N is represented by a vector of size M * N.

#[derive(Clone, Debug, PartialEq)]
pub struct Matrix {
        elements: Vec<Scalar>,
        rows: u32,
        columns: u32
}

impl Matrix {
        // Initialize a new matrix of the given sizes and fills it with the provided default value.
        fn new(r:u32, c:u32, default:Scalar)->Self {
                Matrix{
                        rows:r,
                        columns:c,
                        elements : vec![Scalar::from(default); (r*c) as usize],
                }
        }

        fn print(&self) {
                let col:u32 = self.columns;
                for i in 0..self.rows{
                        let j : usize = (i*col) as usize;
                        println!("{}-th row: {:?}", i, &self.elements[j..j+col as usize]);
                }
        }

        fn inner_product(&self, right : &Matrix)->Matrix{
                assert_eq!(self.rows, right.rows);
                assert_eq!(self.columns, right.columns);
                let mut inner_product:Matrix = Matrix::new(self.rows, right.columns,Scalar::zero());
                        for i in 0..self.rows{
                                for j in 0..self.columns{
                                        let k: usize = (i*self.columns + j) as usize;
                                        inner_product.elements[k] =
                                                        self.elements[k] * right.elements[k];
                                }
                        }
                inner_product
        }

        fn new_random(rows:u32, columns:u32 )->Matrix{
                let mut random: Matrix = Matrix::new(rows, columns, Scalar::zero());
                let d = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("Duration since UNIX_EPOCH failed");
                let mut rng = StdRng::seed_from_u64(d.as_secs());
                for i in 0..rows {
                        for j in 0..columns{
                                let k: usize = (i*columns + j) as usize;
                                random.elements[k] = Scalar::random(&mut rng);
                        }
                }
                random
        }
}


impl Neg for Matrix {
        type Output = Matrix;
        fn neg (self) -> Matrix {
                let mut negated:Matrix = Matrix::new(self.rows, self.columns,Scalar::zero());
                        for i in 0..self.rows{
                                for j in 0..self.columns{
                                        let k: usize = (i*self.columns + j) as usize;
                                        negated.elements[k] = -self.elements[k];
                                }
                        }
                negated
        }
}
impl Add<Matrix> for Matrix {
        type Output = Matrix;
        fn add (self, right : Matrix) -> Matrix {
                assert_eq!(self.rows, right.rows);
                assert_eq!(self.columns, right.columns);
                let mut sum:Matrix = Matrix::new(self.rows, self.columns,Scalar::zero());
                        for i in 0..self.rows{
                                for j in 0..self.columns{
                                        let k = (i * self.columns + j) as usize;
                                        sum.elements[k] =
                                                        self.elements[k] + right.elements[k];
                                }
                        }
                sum
        }
}

impl Sub<Matrix> for Matrix {
        type Output = Matrix;
        fn sub (self, right : Matrix) -> Matrix {
                assert_eq!(self.rows, right.rows);
                assert_eq!(self.columns, right.columns);
                let mut sum:Matrix = Matrix::new(self.rows, self.columns,Scalar::zero());
                        for i in 0..self.rows{
                                for j in 0..self.columns{
                                        let k = (i * self.columns + j) as usize;
                                        sum.elements[k] =
                                                        self.elements[k] - right.elements[k];
                                }
                        }
                sum
        }
}

#[derive(Clone, Debug, PartialEq)]

// The Polynomial struct explicitly stores its degree. Coefficient vectors can be initialized with excessed capacity.
// The first element of the coefficients vector coeffs[0] is the polynomial's free term
// The coeffs[degree] is the leading coefficient of the polynomial.
pub struct Polynomial {
        degree: usize,
        coeffs: Vec<Scalar>,
}


impl Polynomial {
        // The default polynomial is the constant 1.
        fn default() -> Self {
                Polynomial{
                        degree: 0,
                        coeffs : vec![Scalar::one(); 1],
                }
        }

        // "new" function takes as parameter the expected degree of the polynomial and reserves enough capacity for the coefficient vector.
        // A vector of size degree + 1 is reserved for storing all coefficients.
        fn new (expected_degree:usize) -> Polynomial {
                let mut vec = vec!(Scalar::zero(); expected_degree + 1);
                vec[0] = Scalar::one();
                Polynomial {
                        degree:0,
                        coeffs: vec,
                }
        }

        fn init(d:usize, c: Vec<Scalar>) -> Polynomial {
                assert_eq!(d+1, c.len());
                Polynomial{
                        degree:d,
                        coeffs: c,
                }
        }

        // "Add_factor" function multiples the given polynomial P(x) with the provided linear (a * x + b).
        fn add_factor(&mut self, a: Scalar, b:Scalar) -> &Polynomial {


                let old = self.coeffs.clone();
                let old_degree = self.degree;

                if a != Scalar::zero() {

                        self.degree = self.degree + 1;
                        // Check if there is enough capacity in the coefficients vector to store the updated coefficients and resize it otherwise.
                        // Note, that the polynomial can be created with the expected maximum capacity.
                        if self.coeffs.len() < self.degree + 1 {
                                self.coeffs.resize(self.degree + 1, Scalar::zero());
                        }
                        self.coeffs[self.degree] = (a * old[self.degree - 1]);
                }
                for k in 1..=old_degree{
                        self.coeffs[k] = b * old[k] + a * old[k-1];
                }
                self.coeffs[0] = b * old[0];

                self
        }
        // "eval" computes the polynomial evaluation value at the given point x.
        fn eval(&self, point:Scalar) -> Scalar {
                let mut value = Scalar::zero();
                let mut x:Scalar = Scalar::one();

                for i in 0..=self.degree {
                        value += self.coeffs[i] * x;
                        x *= point;
                }

                value
        }

        fn print(&self) {
                println!("The polynomial degree is {}", self.degree);
                println!("The coefficients are {:?}", &self.coeffs);
        }
}

#[derive(Copy, Clone, Debug)]
pub struct R1ProofInitialMessage{
        A       : RistrettoPoint,
        B       : RistrettoPoint,
	C       : RistrettoPoint,
        D       : RistrettoPoint,
}

impl Default for R1ProofInitialMessage {
        fn default() -> Self {
                R1ProofInitialMessage{
                        A: RISTRETTO_BASEPOINT_POINT,
                        B: RISTRETTO_BASEPOINT_POINT,
                        C: RISTRETTO_BASEPOINT_POINT,
                        D: RISTRETTO_BASEPOINT_POINT,
                }
        }
}

impl UpdateTranscript for R1ProofInitialMessage{
        fn update_transcript(&self, transcript: &mut Transcript) -> Result<()> {
                transcript.append_domain_separator(OOON_PROOF_CHALLENGE_LABEL);
                transcript.append_validated_point(b"A", &self.A.compress())?;
                transcript.append_validated_point(b"B", &self.B.compress())?;
                transcript.append_validated_point(b"C", &self.C.compress())?;
                transcript.append_validated_point(b"D", &self.D.compress())?;
                Ok(())
        }
}

#[derive(Clone, Debug)]
pub struct R1ProofFinalResponse{
        f_elements : Vec<Scalar>,
	zA      : Scalar,
        zC      : Scalar,
        m    : u32,
        n   : u32,
}

impl R1ProofFinalResponse{
        fn new ( base: u32, exp : u32) -> Self{
                R1ProofFinalResponse {
                        m : exp,
                        n : base,
                        zA : Scalar::zero(),
                        zC : Scalar::zero(),
                        f_elements : Vec::with_capacity((exp * (base-1)) as usize),
                }

        }
}
pub struct R1Prover {
        a_values : Vec<Scalar>,
        b_matrix : Matrix,
        rA : Scalar,
        rB : Scalar,
        rC : Scalar,
        rD : Scalar,
        m  : u32,
        n  : u32,
}

pub struct R1ProverAwaitingChallenge {
        // The bit-value matrix, where each row contains only one 1
        b_matrix : Matrix,
        // The randomness used for committing to the bit matrix
        rB       : Scalar,
        m : u32,
        n : u32,
}

impl R1ProverAwaitingChallenge{
        pub fn new(bit_matrix : &Matrix, random : &Scalar, rows: u32, columns : u32) -> Self {
                R1ProverAwaitingChallenge {
                        b_matrix : bit_matrix.clone(),
                        rB : random.clone(),
                        m : rows,
                        n : columns
                }
        }
}

impl AssetProofProverAwaitingChallenge for R1ProverAwaitingChallenge {
        type ZKInitialMessage = R1ProofInitialMessage;
        type ZKFinalResponse = R1ProofFinalResponse;
        type ZKProver = R1Prover;

        fn generate_initial_message<T: RngCore + CryptoRng> (
                &self,
                p_gens: &PedersenGens,
                rng: &mut T,
        ) -> (Self::ZKProver, Self::ZKInitialMessage) {

                let rows = self.b_matrix.rows;
                let columns= self.b_matrix.columns;
                let generators = OooNProofGenerators::new(rows, columns);

                let mut a_values : Vec<Scalar> = Vec::with_capacity((rows * columns) as usize);
                for k in 0..(rows * columns) as usize{
                        a_values.push( Scalar::random(rng));
                }

                let random_A = Scalar::random(rng);
                let random_C = Scalar::random(rng);
                let random_D = Scalar::random(rng);

                let ONE = Matrix::new(rows, columns, Scalar::one());
                let TWO = Matrix::new(rows, columns, Scalar::one() + Scalar::one());

                let mut initial_message : R1ProofInitialMessage;

                let mut a_matrix = Matrix {
                        rows     : rows,
                        columns  : columns,
                        elements : a_values.clone(),
                };

                let mut sum : Scalar;
                for r in 0..a_matrix.rows{
                        sum = Scalar::zero();
                        for c in 1..a_matrix.columns{
                              sum += a_matrix.elements[(r * a_matrix.columns + c) as usize]
                        }
                        //The first element of each row is the negated sum of the row's other elements.
                        a_matrix.elements[(r * a_matrix.columns) as usize] = -sum;
                }

                let c_matrix : Matrix = a_matrix.clone().inner_product(&(ONE - TWO.inner_product(&self.b_matrix)));
                let d_matrix : Matrix = - (a_matrix.clone().inner_product(&a_matrix)); // Implement an associated function taking two matrix parameters
                (
                        R1Prover{
                                a_values : a_matrix.elements.clone(),
                                b_matrix : self.b_matrix.clone(),
                                rB : self.rB.clone(),
                                rA : random_A,
                                rC : random_C,
                                rD : random_D,
                                m : rows,
                                n : columns,
                        },

                        R1ProofInitialMessage{
                                A : generators.vector_commit(&a_matrix.elements, random_A),
                                B : generators.vector_commit(&self.b_matrix.elements, self.rB),
                                C : generators.vector_commit(&c_matrix.elements, random_C),
                                D : generators.vector_commit(&d_matrix.elements, random_D),
                        }
                )
        }
}

impl AssetProofProver<R1ProofFinalResponse> for R1Prover{
        fn apply_challenge(&self, c: &ZKPChallenge) -> R1ProofFinalResponse{

                let mut f_values : Vec<Scalar> = Vec::with_capacity((self.m * (self.n-1)) as usize);
                for i in 0..self.m {
                        for j in 0..(self.n-1) {
                                f_values.push(self.b_matrix.elements[(i * self.n + j + 1) as usize] * c.x + self.a_values[(i * self.n + j + 1) as usize]);
                        }

                }

                R1ProofFinalResponse{
                        f_elements : f_values,
                        zA : self.rA + c.x * self.rB,
                        zC : self.rD + c.x * self.rC,
                        m : self.m,
                        n : self.n,
                }
        }
}

pub struct R1ProofVerifier {
        B : RistrettoPoint,
}

impl R1ProofVerifier {
        pub fn new(bit_commitment : &RistrettoPoint)-> Self{
                R1ProofVerifier{
                        B : bit_commitment.clone(),
                }
        }
}

impl AssetProofVerifier for R1ProofVerifier {
        type ZKInitialMessage = R1ProofInitialMessage;
        type ZKFinalResponse = R1ProofFinalResponse;

        fn verify(
                &self,
                pc_gens : &PedersenGens,
                c : &ZKPChallenge,
                initial_message : &Self::ZKInitialMessage,
                final_response : & Self::ZKFinalResponse,
        ) -> Result<()> {

                let rows = final_response.m;
                let columns = final_response.n;

                let mut f_matrix = Matrix::new(rows, columns, c.x);
                let x_matrix = Matrix::new(rows, columns, c.x);

                let generators = OooNProofGenerators::new(rows, columns);

                for i in 0..rows {
                        for j in 1..columns{
                                f_matrix.elements[(i * columns + j) as usize] = final_response.f_elements[(i * (columns - 1) + (j-1)) as usize];
                                f_matrix.elements[(i * columns) as usize] -= &final_response.f_elements[(i * (columns - 1) + (j-1)) as usize];
                        }
                }

                let com_f  = generators.vector_commit(&f_matrix.elements, final_response.zA);
                let com_fx = generators.vector_commit(&f_matrix.inner_product(&(x_matrix - f_matrix.clone())).elements, final_response.zC);

                ensure!(
                        c.x * initial_message.B + initial_message.A == com_f,
                        AssetProofError::R1FinalResponseVerificationError { check : 1 }
                );

                ensure!(
                        c.x * initial_message.C + initial_message.D == com_fx,
                        AssetProofError::R1FinalResponseVerificationError { check : 2 }
                );

                Ok(())

        }
}


#[derive(Clone, Debug)]
pub struct OOONProofInitialMessage{
        r1_proof_initial_message : R1ProofInitialMessage,
        G_vec  : Vec<RistrettoPoint>,
        n      : u32,
        m      : u32,
}

impl OOONProofInitialMessage {
        fn new (base: u32, exp: u32) -> Self {
                OOONProofInitialMessage{
                        r1_proof_initial_message : R1ProofInitialMessage::default(),
                        G_vec : Vec::with_capacity(exp as usize),
                        n : base,
                        m : exp,
                }
        }
}

impl Default for OOONProofInitialMessage {
        fn default() -> Self {
                OOONProofInitialMessage::new(4,3) // TODO: Replace these constants with system-wide parameters for the BASE and EXPONENT
        }
}

impl UpdateTranscript for OOONProofInitialMessage{
        fn update_transcript(&self, transcript: &mut Transcript) -> Result<()> {
                transcript.append_domain_separator(OOON_PROOF_CHALLENGE_LABEL);
                self.r1_proof_initial_message.update_transcript(transcript);
                for k in 0..self.m as usize{
                        transcript.append_validated_point(b"Gk", &self.G_vec[k].compress());
                }

                Ok(())
        }
}

#[derive(Clone, Debug)]
pub struct OOONProofFinalResponse{
        r1_proof_final_response : R1ProofFinalResponse,
	z  : Scalar,
        m  : u32,
        n  : u32,
}

pub struct OOONProver {
        rho_values : Vec<Scalar>,
        r1_prover : R1Prover,
        m  : u32,
        n  : u32,
}

pub struct OOONProverAwaitingChallenge {
        // The index of the secret commitment in the given list, which is opening to zero and is blinded by "random"
        secret_index : u32,
        // The randomness used for committing to the bit matrix
        random  : Scalar,
        // The list of N commitments where one commitment is opening to 0. (#TODO Find a way to avoid of cloning this huge data set)
        commitments : Vec<RistrettoPoint>,
        base : u32,
        exp : u32,
}

impl OOONProverAwaitingChallenge{
        pub fn new(l : u32, r : &Scalar, commitments_ref: &Vec<RistrettoPoint>, m: u32, n : u32) -> Self {
                OOONProverAwaitingChallenge {
                        secret_index : l,
                        random : r.clone(),
                        commitments : commitments_ref.clone(),
                        exp : m,
                        base : n,
                }
        }
}

impl AssetProofProverAwaitingChallenge for OOONProverAwaitingChallenge {
        type ZKInitialMessage = OOONProofInitialMessage;
        type ZKFinalResponse = OOONProofFinalResponse;
        type ZKProver = OOONProver;

        fn generate_initial_message<T: RngCore + CryptoRng> (
                &self,
                pc_gens: &PedersenGens,
                rng: &mut T,
        ) -> (Self::ZKProver, Self::ZKInitialMessage) {

                let columns = self.base;
                let rows = self.exp;
                let N = self.base.pow(self.exp) as usize;
                let generators = OooNProofGenerators::new(rows, columns);

                // We require the actual size of the provided list of commitments to be equal to N = n^m
                // In case of smaller list, we should pad the commitment list with the last element to make the commitment vector of size N.
                // We assume the list is padded already before being passed to the OOON proof initialization process.
                // IMPORTANT: This check has critical security importance
                assert_eq!(N,  self.commitments.len());

                let mut rho : Vec<Scalar> = Vec::with_capacity(self.exp as usize);
                for k in 0..self.exp  as usize{
                        rho.push(Scalar::random(rng));
                }

                let l_bit_matrix = convert_to_matrix_rep(self.secret_index, self.base, self.exp);
                let mut i_rep : Vec<u32> = Vec::with_capacity(self.exp as usize);
                let b_comm = generators.vector_commit(&l_bit_matrix, self.random);

                let b_matrix_rep = Matrix{
                        rows : rows,
                        columns : columns,
                        elements : l_bit_matrix.clone(),
                };

                let r1_prover = R1ProverAwaitingChallenge::new(&b_matrix_rep, &self.random, rows, columns);

                let (r1_prover, r1_initial_message) = r1_prover.generate_initial_message(pc_gens, rng);

                let one = Polynomial::new(self.exp as usize);
                let mut polynomials : Vec<Polynomial> = vec![one; N];

                for I in 0..N as usize {
                        i_rep = convert_to_base(I as u32, self.base, self.exp);
                        for k in 0..self.exp as usize{
                                 let t = k * self.base as usize + i_rep[k] as usize;
                                 polynomials[I].add_factor(l_bit_matrix[t], r1_prover.a_values[t]);
                        }
                }

                let mut G_values : Vec<RistrettoPoint> = Vec::with_capacity(self.exp as usize);
                for k in 0..self.exp as usize {
                        G_values.push(rho[k] * generators.com_gens.B_blinding); // #TODO: Double check if this matches the El-Gamal generators.
                        for I in 0..N {
                                G_values[k] += (polynomials[I].coeffs[k]) * self.commitments[I];
                        }
                }

                (
                        OOONProver {
                                rho_values : rho,
                                r1_prover : r1_prover,
                                m  : self.exp,
                                n  : self.base,
                        },

                        OOONProofInitialMessage{
                                r1_proof_initial_message : r1_initial_message,
                                G_vec  : G_values,
                                m  : self.exp,
                                n  : self.base,
                        }
                )
        }
}

impl AssetProofProver<OOONProofFinalResponse> for OOONProver{
        fn apply_challenge(&self, c: &ZKPChallenge) -> OOONProofFinalResponse{

                let r1_final_response = self.r1_prover.apply_challenge(c);

                let mut y = Scalar::one();
                let mut z = Scalar::zero();

                for k in 0..self.m as usize {
                        z -= y * self.rho_values[k];
                        y *= c.x;
                }

                z += self.r1_prover.rB * y;

                OOONProofFinalResponse{
                        r1_proof_final_response : r1_final_response,
                        z  : z,
                        m  : self.m,
                        n  : self.n,
                }

        }
}

pub struct OOONProofVerifier {
        commitment_list: Vec<RistrettoPoint>,
}

impl OOONProofVerifier {
        pub fn new(list : & Vec<RistrettoPoint>)-> Self{
                OOONProofVerifier{
                        commitment_list : list.clone(),
                }
        }
}

impl AssetProofVerifier for OOONProofVerifier {
        type ZKInitialMessage = OOONProofInitialMessage;
        type ZKFinalResponse = OOONProofFinalResponse;

        fn verify(
                &self,
                pc_gens : &PedersenGens,
                c : &ZKPChallenge,
                initial_message : &Self::ZKInitialMessage,
                final_response : & Self::ZKFinalResponse,
        ) -> Result<()> {

                let N = final_response.n.pow(final_response.m) as usize;
                let m = final_response.m as usize;
                let n = final_response.n as usize;
                let generators = OooNProofGenerators::new(final_response.m, final_response.n);

                let b_comm = initial_message.r1_proof_initial_message.B;
                let r1_verifier = R1ProofVerifier::new(&b_comm);

                let result_r1 = r1_verifier.verify(pc_gens,
                                                        c,
                                                        &initial_message.r1_proof_initial_message,
                                                        &final_response.r1_proof_final_response
                                                );
                ensure!(
                        result_r1.is_ok(),
                        AssetProofError::OOONFinalResponseVerificationError { check : 1 }
                );

                let mut f_values = vec![c.x; m * n];
                let proof_f_elements = &final_response.r1_proof_final_response.f_elements;

                for i in 0..m {
                        for j in 1..n{
                                f_values[(i * n + j) as usize] = proof_f_elements[(i * (n - 1) + (j-1)) as usize];
                                f_values[(i * n) as usize] -= proof_f_elements[(i * (n - 1) + (j-1)) as usize];
                        }
                }

                let mut p_i : Scalar;
                let mut left : RistrettoPoint =  RistrettoPoint::default();
                let right = final_response.z * generators.com_gens.B_blinding;

                for i in 0..N {
                        p_i  =  Scalar::one();
                        let i_rep = convert_to_base(i as u32, n as u32, m as u32);
                        for j in 0..m {
                                p_i *= f_values [j * n + i_rep[j] as usize];
                        }
                        left += (p_i * self.commitment_list[i]);
                }
                let mut temp = Scalar::one();
                for k in 0..m {
                        left -= temp * initial_message.G_vec[k];
                        temp *= c.x;
                }

                ensure!(
                        left == right, AssetProofError::OOONFinalResponseVerificationError {check : 2}
                );

                Ok(())
        }
}

// End of new OOON code



#[cfg(test)]
mod tests {
        extern crate wasm_bindgen_test;
        use super::*;
        use crate::asset_proofs::*;
        use rand::{rngs::StdRng, SeedableRng};
        use wasm_bindgen_test::*;

        const SEED_1: [u8; 32] = [42u8; 32];


        #[test]
        #[wasm_bindgen_test]
        fn test_ooon_proof_api(){
                let pc_gens = PedersenGens::default();
                let mut rng = StdRng::from_seed(SEED_1);

                let mut transcript = Transcript::new(OOON_PROOF_LABEL);

                const BASE : u32 = 4; //n = 3 : COLUMNS
                const EXPONENT : u32= 3; //m = 2 : ROWS
                let generators = OooNProofGenerators::new(EXPONENT, BASE);

                let N = 64; // 4^3
                let size : usize =64 ;

                let rB = Scalar::random(&mut rng);
                let C_secret = rB * generators.com_gens.B_blinding ;

                let mut commitments = vec![Scalar::random(&mut rng) * generators.com_gens.B + Scalar::random(&mut rng) * generators.com_gens.B_blinding; N];

                for l in 5..size as u32 {

                        commitments[l as usize] = C_secret;

                        let prover = OOONProverAwaitingChallenge::new(l, &rB, &commitments, EXPONENT, BASE);

                        let verifier = OOONProofVerifier::new(&commitments);
                        let (prover, initial_message) = prover.generate_initial_message(&pc_gens, &mut rng);

                        initial_message.update_transcript(&mut transcript).unwrap();
                        let challenge = transcript.scalar_challenge(OOON_PROOF_CHALLENGE_LABEL);

                        let final_response = prover.apply_challenge(&challenge);

                        let result = verifier.verify(&pc_gens, &challenge, &initial_message, &final_response);
                        assert!(result.is_ok());
                }
        }

        #[test]
        #[wasm_bindgen_test]
        fn test_r1_proof_api(){
                let pc_gens = PedersenGens::default();
                let mut rng = StdRng::from_seed(SEED_1);


                let mut transcript = Transcript::new(OOON_PROOF_LABEL);

                const BASE : u32 = 4; //n = 3 : COLUMNS
                const EXPONENT : u32= 3; //m = 2 : ROWS
                let generators = OooNProofGenerators::new(EXPONENT, BASE);


                let mut base_matrix : Vec<Scalar>;
                let mut b : Matrix;
                for i in 0..64
                {
                        base_matrix = convert_to_matrix_rep(i, BASE , EXPONENT );

                        b = Matrix{
                                rows : EXPONENT,
                                columns : BASE,
                                elements : base_matrix.clone(),
                        };
                        let r = Scalar::from(45728u32);
                        let b_comm = generators.vector_commit(&base_matrix, r);
                        let prover = R1ProverAwaitingChallenge::new(&b, &r, EXPONENT, BASE);

                        let verifier = R1ProofVerifier::new(&b_comm);
                        let (prover, initial_message) = prover.generate_initial_message(&pc_gens, &mut rng);

                        initial_message.update_transcript(&mut transcript).unwrap();

                        let challenge = transcript.scalar_challenge(OOON_PROOF_CHALLENGE_LABEL);

                        let final_response = prover.apply_challenge(&challenge);

                        let result = verifier.verify(&pc_gens, &challenge, &initial_message, &final_response);
        
                        assert!(result.is_ok());
                }
        }


        // #[test]
        //#[wasm_bindgen_test]
        fn test_polynomials(){

                println!("TESTING POLYNOMIALS...");

                let mut p = Polynomial::default();
                let mut p = Polynomial::new(6);

                p.add_factor(Scalar::from(5u32), Scalar::from(7u32));
                p.add_factor(Scalar::from(5u32), Scalar::from(7u32));
                p.add_factor(Scalar::from(5u32), Scalar::from(7u32));
                p.add_factor(Scalar::from(5u32), Scalar::from(7u32));
                p.add_factor(Scalar::from(5u32), Scalar::from(7u32));
                p.add_factor(Scalar::from(5u32), Scalar::from(7u32));
        
                assert_eq!(p.eval(Scalar::from(8u32)), Scalar::from(10779215329u64));
        }
}




















