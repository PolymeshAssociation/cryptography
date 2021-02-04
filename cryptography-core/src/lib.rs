#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

pub use curve25519_dalek::{
    self,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};

pub mod cdd_claim;

pub mod dalek_wrapper;

pub mod asset_proofs;
