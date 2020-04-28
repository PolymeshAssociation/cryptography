// One-out-of-many proof is a Sigma protocol enabling to efficiently prove the knowledge 
// of a secret commitment among the public list of N commitments which is opening to 0
#![allow(non_snake_case)]
use bulletproofs::PedersenGens;
use curve25519_dalek::{ristretto::{RistrettoPoint},constants::RISTRETTO_BASEPOINT_COMPRESSED, traits::MultiscalarMul, constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
//use serde::{Serialize, Deserialize};
use crate::asset_proofs::AssetProofError;
//use crate::asset_proofs::{
//                encryption_proofs::{
//                        AssetProofProver,
//                },
//                transcript::{TranscriptProtocol, UpdateTranscript},
//};
use sha3::Sha3_512;
use std::ops::{Add, Sub, Mul, Neg};
use std::convert::TryInto;
use rand::{rngs::StdRng, SeedableRng};
const SEED_1: [u8; 32] = [42u8; 32];

use std::time::SystemTime;
use merlin::Transcript;
//use crate::transcript::TranscriptProtocol;
//use crate::matrix::Matrix;


const BASE : u32 = 3;
const EXPONENT : u32 = 2;
const OOON_PROOF_LABEL : &[u8;14] = b"PolymathMERCAT";

// ********************************************************************************************************************
// ** BEGINING OF THE GENERATORS & UTILS MODULE. IN THE FUTURE THIS PART OF THE CODE SHOULD RESIDE IN SEPARATE FILES **
// ********************************************************************************************************************

// This utility function is developed for support testing.
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

struct R1ProofWitness {
        a_values : Vec<Scalar>,
        rA : Scalar,
        rC : Scalar,
        rD : Scalar,
        
}

impl R1ProofWitness {
        fn new (rows:u32, col:u32) -> R1ProofWitness{
                let d = SystemTime::now().
                                duration_since(SystemTime::UNIX_EPOCH).
                                expect("Duration since UNIX_EPOCH failed");
                let mut rng = StdRng::seed_from_u64(d.as_secs());
                let mut a = vec![Scalar::zero(); (rows * col) as usize];
                
                for k in 0..(rows * col) as usize{
                        a[k] = Scalar::random(&mut rng);
                }
               

                R1ProofWitness{
                        a_values : a,
                        rA : Scalar::random(&mut rng),
                        rC : Scalar::random(&mut rng),
                        rD : Scalar::random(&mut rng),
                       
                }
                
        }
}
pub struct R1Proof{
        A       : RistrettoPoint,
        B       : RistrettoPoint,
	C       : RistrettoPoint,
        D       : RistrettoPoint,
        f_elements : Vec<Scalar>,
	zA      : Scalar,
        zC      : Scalar,
        m    : u32,
        n   : u32,
} 

impl  R1Proof {
        fn new(rows:u32, columns:u32)->R1Proof {
                R1Proof{
                        A  : RISTRETTO_BASEPOINT_POINT,
                        B  : RISTRETTO_BASEPOINT_POINT,
                        C  : RISTRETTO_BASEPOINT_POINT,
                        D  : RISTRETTO_BASEPOINT_POINT,
                        f_elements : vec![Scalar::zero(); (rows * (columns - 1)) as usize],
                        zA : Scalar::zero(),
                        zC : Scalar::zero(),  
                        m : rows,
                        n  : columns,
                }
        }
        fn initialize_proof(b_matrix : &Matrix, rB : &Scalar, witness : & R1ProofWitness, generators : &OooNProofGenerators,  rows : u32, columns:u32) -> R1Proof {
                
                assert_eq!(witness.a_values.len() as u32, columns * rows);
                //assert_eq!(witness.base, columns);

                let ONE = Matrix::new(rows, columns, Scalar::one());
                let TWO = Matrix::new(rows, columns, Scalar::one() + Scalar::one());
                
                let mut proof : R1Proof = R1Proof::new(rows,columns);
                
                let mut a_matrix = Matrix {
                        rows     : rows,
                        columns  : columns, 
                        elements : witness.a_values.clone(),
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
                
                let c_matrix : Matrix = a_matrix.clone().inner_product(&(ONE - TWO.inner_product(&b_matrix)));
                let d_matrix : Matrix = - (a_matrix.clone().inner_product(&a_matrix)); // Implement an associated functin taking two matrix parameters
                
               
                proof.A = generators.vector_commit(&a_matrix.elements, witness.rA);
                proof.B = generators.vector_commit(&b_matrix.elements, *rB);
                proof.C = generators.vector_commit(&c_matrix.elements, witness.rC);
                proof.D = generators.vector_commit(&d_matrix.elements, witness.rD);
            
                proof
        }


        fn finalize_proof(& mut self, x: &Scalar, b_matrix: & Matrix, rB : & Scalar, witness: & R1ProofWitness) {
              
                
                for i in 0..self.m {
                        for j in 0..(self.n-1) {
                                self.f_elements[(i * (self.n - 1) + j) as usize] = 
                                                b_matrix.elements[(i * self.n + j + 1) as usize] * x + witness.a_values[(i * self.n + j + 1) as usize];
                        }

                }
               
                self.zA = witness.rA + x * rB;
                self.zC = witness.rD + x * witness.rC;

                
        }

        fn prove(b_matrix : &Matrix, rB : &Scalar, rows: u32, columns : u32) ->R1Proof {
                let generators = OooNProofGenerators::new(rows, columns);

                let mut prover = Transcript::new(b"r1prooftest");
                

                let witness = R1ProofWitness::new(rows, columns);
                let mut proof = R1Proof::initialize_proof(b_matrix, rB, & witness, & generators, rows, columns);
                

                prover.append_message(b"A", proof.A.clone().compress().as_bytes());
                prover.append_message(b"B", proof.B.compress().as_bytes());
                prover.append_message(b"C", proof.C.compress().as_bytes());
                prover.append_message(b"D", proof.D.compress().as_bytes());
                
                let mut buf = [0u8; 64];
                prover.challenge_bytes(b"x", &mut buf);
                
                let x: Scalar = Scalar::from_bytes_mod_order_wide(&buf);             

                proof.finalize_proof(&x, b_matrix, rB, &witness);       
                      

                proof
        }

       
        fn verify_with_challenge(proof : & R1Proof, x : & Scalar, generators : & OooNProofGenerators, rows: u32, columns: u32) -> bool{
                println!("R1proof VERIFY1 has started...");
                let mut f_matrix = Matrix::new(rows, columns, *x);
                let mut x_matrix = Matrix::new(rows, columns, *x);

                for i in 0..rows {
                        for j in 1..columns{
                                f_matrix.elements[(i * columns + j) as usize] = proof.f_elements[(i * (columns - 1) + (j-1)) as usize];
                                f_matrix.elements[(i * columns) as usize] -= &proof.f_elements[(i * (columns - 1) + (j-1)) as usize];
                        }
                }
                
                let com_f  = generators.vector_commit(&f_matrix.elements, proof.zA);
                let com_fx = generators.vector_commit(&f_matrix.inner_product(&(x_matrix - f_matrix.clone())).elements, proof.zC);

                assert_eq!(x * proof.B + proof.A, com_f);
                assert_eq!(x * proof.C + proof.D, com_fx);
                true
        }

        fn verify(proof : & R1Proof, rows: u32, columns: u32) -> bool {
                println!("R1proof verification has started...");
                let mut verifier = Transcript::new(b"r1prooftest");
                let generators = OooNProofGenerators::new(rows, columns);
                
                let mut buf = [0u8; 64];
                verifier.append_message(b"A", proof.A.compress().as_bytes());
                verifier.append_message(b"B", proof.B.compress().as_bytes());
                verifier.append_message(b"C", proof.C.compress().as_bytes());
                verifier.append_message(b"D", proof.D.compress().as_bytes());                
                verifier.challenge_bytes(b"x", &mut buf);

                let x: Scalar = Scalar::from_bytes_mod_order_wide(&buf);       
                return R1Proof::verify_with_challenge(proof, &x, &generators, rows, columns);
                //println!("The Verifier challenge value is {:?}", x);     
                
        }
}

// ** END OF THE R1Proof MODULE. IN THE FUTURE THIS PART OF THE CODE SHOULD RESIDE IN A SEPARATE FILE **
// *************************************************************************************************************

// *************************************************************************************************************
// ** BEGINING OF THE 1OON_PROOF MODULE. IN THE FUTURE THIS PART OF THE CODE SHOULD RESIDE IN A SEPARATE FILE **

pub struct OooNProof{
        r1_proof : R1Proof,
        G_vec  : Vec<RistrettoPoint>,
        z        : Scalar,
        base     : u32, // n
        exp      : u32, // m
}

impl OooNProof{
        fn new(n: u32, m:u32) -> OooNProof{
                OooNProof{
                        base     : n,
                        exp      : m,
                        G_vec  : vec!(RISTRETTO_BASEPOINT_POINT; m as usize),
                        r1_proof : R1Proof::new(n, m),
                        z        : Scalar::zero(),
                }
        }    
        
        
        fn prove (&mut self, commitments: & mut Vec<RistrettoPoint>, l : u32, rB: &Scalar, generators: &OooNProofGenerators){
                
                
                let d = SystemTime::now().
                                duration_since(SystemTime::UNIX_EPOCH).
                                expect("Duration since UNIX_EPOCH failed");
                let mut rng = StdRng::seed_from_u64(d.as_secs());

                // We require the actual size of the provided list of commitments to be equal to N = n^m
                let N = self.base.pow(self.exp) as usize;

                // In case of smaller list, we pad the commitment list with the last element to make the commitment vector of size N.
                // IMPORTANT: This step has critical security importance
                if N  > commitments.len()  {
                        let last = commitments[commitments.len() - 1];
                        commitments.resize(N, last);
                }

                let mut rho = vec!(Scalar::zero(); self.exp as usize);
                for k in 0..self.exp  as usize{
                        rho[k] = Scalar::random(&mut rng);
                }
                
                //let rB = Scalar::random(&mut rng);                 
                let mut r1_proof_randoms = R1ProofWitness::new(self.exp, self.base);

                let mut sum : Scalar;
                for r in 0..self.exp{
                        sum = Scalar::zero();
                        for c in 1..self.base{
                              sum += r1_proof_randoms.a_values[(r * self.base + c) as usize]  
                        }
                        //The first element of each row is the negated sum of the row's other elements. 
                        r1_proof_randoms.a_values[(r * self.base) as usize] = -sum; 
                }

                let l_bit_matrix = convert_to_matrix_rep(l, self.base, self.exp);     


                let mut i_rep : Vec<u32> = Vec::with_capacity(self.exp as usize);

                //compute the polynomials P_i(X) for i = 0,..,N-1
                let one = Polynomial::new(self.exp as usize);
                
                let mut polynomials : Vec<Polynomial> = vec![one; N];


                for I in 0..N as usize {
                        i_rep = convert_to_base(I as u32, self.base, self.exp);
                        
                        for k in 0..self.exp as usize{
                                let t = k * self.base as usize + i_rep[k] as usize;
                                polynomials[I].add_factor(l_bit_matrix[t], r1_proof_randoms.a_values[t]);                                                                      
                        }             
                }
           
                for k in 0..self.exp as usize {
                        self.G_vec[k] = (rho[k] * generators.com_gens.B_blinding); // #TODO: Double check if this matches the El-Gamal generators.
                        for I in 0..N {
                                self.G_vec[k] += (polynomials[I].coeffs[k]) * commitments[I];
                        }
                }

                let l_matrix = Matrix{
                        rows    : self.exp,
                        columns : self.base,
                        elements: l_bit_matrix,
                };    

                self.r1_proof = R1Proof::initialize_proof(&l_matrix, &rB, & r1_proof_randoms, generators, self.exp, self.base);
                let x = Scalar::one() + Scalar::one(); // Change this line to generate the challenge with Fiat-Shamir trick.
                self.r1_proof.finalize_proof( &x, &l_matrix, &rB,  & r1_proof_randoms);//&x, b_matrix, rB, &witness

                let mut y = Scalar::one();
                
                self.z = Scalar::zero();
                for k in 0..self.exp as usize {
                        self.z -= y * rho[k];
                        y *= x;
                }
                
                self.z += rB * y;
        }

        fn verify(proof: & OooNProof,  x : & Scalar, generators : &OooNProofGenerators, commitments : & Vec<RistrettoPoint>) {
                
                let m = proof.exp as usize;
                let n = proof.base as usize;
                let N = proof.base.pow(proof.exp) as usize;
                println!("OOON Proof Verification Started....");

                R1Proof::verify_with_challenge(&proof.r1_proof, &x, generators, proof.exp, proof.base);
                let mut f_values = vec![*x; m * n];

                for i in 0..m {
                        for j in 1..n{
                                f_values[(i * n + j) as usize] = proof.r1_proof.f_elements[(i * (n - 1) + (j-1)) as usize];
                                f_values[(i * n) as usize] -= &proof.r1_proof.f_elements[(i * (n - 1) + (j-1)) as usize];
                        }
                }

               
                let mut p_i : Scalar; 
                let mut left : RistrettoPoint =  RistrettoPoint::default();
                let right = proof.z * generators.com_gens.B_blinding;


                for i in 0..N {
                        p_i  =  Scalar::one();
                        let i_rep = convert_to_base(i as u32, n as u32, m as u32);
                        for j in 0..m {
                                p_i *= f_values [j * n + i_rep[j] as usize];
                        }                                     
                        left += (p_i * commitments[i]);
                }
                let mut temp = Scalar::one();
                for k in 0..m {
                        left -= temp * proof.G_vec[k];  
                        temp *= x;
                }

                assert_eq!(left, right);

                println!("OOON Verification Passed");
                

                
        }

                

        
}



// ** END OF THE 1OON_PROOF MODULE. IN THE FUTURE THIS PART OF THE CODE SHOULD RESIDE IN A SEPARATE FILE **
// *************************************************************************************************************


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
fn test_ooon_proofs(){
        println!("TESTING 1-out-of-Many Proofs...");

        const BASE : u32 = 3; //n = 3 : COLUMNS
        const EXPONENT : u32= 2; //m = 2 : ROWS

        let N = 4;
        let size : usize = 9 ;

        let d = SystemTime::now().
                                duration_since(SystemTime::UNIX_EPOCH).
                                expect("Duration since UNIX_EPOCH failed");
        let mut rng = StdRng::seed_from_u64(d.as_secs());
        
        let generators = OooNProofGenerators::new(EXPONENT, BASE);

        let mut proof = OooNProof::new(BASE, EXPONENT);
        let mut proof1 = OooNProof::new(BASE, EXPONENT);
        
        

        let rB = Scalar::random(&mut rng);            
        let C_secret = rB * generators.com_gens.B_blinding ;
        
        let x = Scalar::one() + Scalar::one(); 

        for l in 0..size{
                print!("{}", l);
                let mut commitments = vec![Scalar::random(&mut rng) * generators.com_gens.B + Scalar::random(&mut rng) * generators.com_gens.B_blinding; size];
                commitments[l] = C_secret;
                proof.prove(&mut commitments, l as u32, &rB, &generators);
                OooNProof::verify(&proof, &x, &generators, & commitments);
        }
        println!("TESTING 1-out-of-Many Proofs FINISHED");

}
#[test]
#[wasm_bindgen_test]
fn test_r1_proofs() {

        println!("TESTING R1Proofs...");

        const BASE : u32 = 4; //n = 3 : COLUMNS
        const EXPONENT : u32= 3; //m = 2 : ROWS


        let mut proof = R1Proof::new(BASE, EXPONENT);
        let mut proof1 = R1Proof::new(BASE, EXPONENT);
        let mut base_matrix : Vec<Scalar>;
        let mut b : Matrix;
        for i in 0..5
        {
                base_matrix = convert_to_matrix_rep(i, BASE , EXPONENT );
                
                b = Matrix{
                        rows : EXPONENT,
                        columns : BASE,
                        elements : base_matrix,
                };
                //proof = R1Proof::prove(&b, &Scalar::from(45728u32), EXPONENT, BASE);
                proof1 = R1Proof::prove(&b, &Scalar::from(45728u32), EXPONENT, BASE);
                let b = R1Proof::verify(&proof1, EXPONENT, BASE);
                println!("The proof for {} has passed", i);
        }

       
}
#[test]
#[wasm_bindgen_test]
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
        p.print();
        println!("The evaluation at point 8 is {:?}", p.eval(Scalar::from(8u32)));
        assert_eq!(p.eval(Scalar::from(8u32)), Scalar::from(10779215329u64));

}


// fn main() {
//         let zero = Scalar::zero();
//         let one = Scalar::one();
//         let messages : Vec<Scalar> = vec![zero,one,zero,zero,one,zero,zero,one,zero,zero,one,zero];
//         let m: Matrix = Matrix::new(3,4,Scalar::from(5u32));
        
//         //test_r1_proofs();

//         //test_polynomials();

//         test_ooon_proofs();

//         let ROWS = EXPONENT;
//         let COLUMNS = BASE;

//         let b = Matrix{
//                 rows : ROWS,
//                 columns : COLUMNS,
//                 elements : vec![zero, zero, one, 
//                                 zero, zero, one],
//         };

       
// 	println!("Hello, 1 out of Many Proofs!");
//         let proof_generators = OooNProofGenerators::new(3,4);
//         let commitment = proof_generators.vector_commit(&messages, one+one);
//         //println!("The vector commitment is {:?}", commitment.compress().to_bytes());
//         //ProofGenerators.print_generators();
// }


}
















