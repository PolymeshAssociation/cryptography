//! PIAL is the library that implements the private identity audit protocol
//! of the PIAL, as defined in the section TODO of the whitepaper TODO.
//!

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

use codec::{Decode, Encode, Error as CodecError, Input, Output};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod errors;
#[macro_use]
mod macros;
mod proofs;
mod prover;
pub mod verifier;
use blake2::{Blake2b, Digest};
use cryptography_core::{
    cdd_claim::{CddClaimData, CddId},
    codec_wrapper::{RistrettoPointEncoder, ScalarEncoder, RISTRETTO_POINT_SIZE, SCALAR_SIZE},
    curve25519_dalek::{
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
    },
};
use errors::Fallible;
use proofs::{FinalResponse, InitialMessage};
use rand_core::{CryptoRng, RngCore};
use sp_std::vec::Vec;
use uuid::Uuid;

/// This is a security parameter. The larger the value, the higher the security guarantees.
/// This value is used to pad the set of private unique ids such that the set,
/// has at least this many element. As a result when a CDD Provider proves that it holds an
/// element of a set, PUIS can guess that element with probability 1/the_size_of_the_padded_set.
pub const SET_SIZE_ANONYMITY_PARAM: usize = 100_000;

pub struct Prover;

pub struct VerifierSetGenerator;
pub struct Verifier;

/// The initial private set of PUIS.
#[derive(PartialEq)]
pub struct PrivateUids(pub Vec<Scalar>);

impl Encode for PrivateUids {
    #[inline]
    fn size_hint(&self) -> usize {
        let mut size_hint = 0;
        for scalar in self.0.iter() {
            size_hint += ScalarEncoder(&scalar).size_hint()
        }
        size_hint
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        for scalar in self.0.iter() {
            ScalarEncoder(scalar).encode_to(dest);
        }
    }
}

impl Decode for PrivateUids {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let raws = <Vec<[u8; SCALAR_SIZE]>>::decode(input)?;

        let inner = raws.into_iter().map(|raw| Scalar::from_bits(raw)).collect();

        Ok(Self(inner))
    }
}

/// The committed and padded version of the private set of PUIS.
#[derive(Clone, Debug, PartialEq)]
pub struct CommittedUids(pub Vec<RistrettoPoint>);

impl Encode for CommittedUids {
    #[inline]
    fn size_hint(&self) -> usize {
        let mut size_hint = 0;
        for point in self.0.iter() {
            size_hint += RistrettoPointEncoder(&point).size_hint()
        }
        size_hint
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        for point in self.0.iter() {
            point.compress().as_bytes().encode_to(dest);
        }
    }
}

impl Decode for CommittedUids {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let mut raws: Vec<[u8; RISTRETTO_POINT_SIZE]> = vec![];

        loop {
            if let Ok(Some(n)) = input.remaining_len() {
                if n == 0 {
                    break;
                }
                raws.push(<[u8; RISTRETTO_POINT_SIZE]>::decode(input)?);
            } else {
                break;
            }
        }

        let inner = raws
            .into_iter()
            .map(|raw| {
                CompressedRistretto(raw)
                    .decompress()
                    .ok_or_else(|| CodecError::from("Invalid compressed `RistrettoPoint`."))
            })
            .collect::<Result<_, _>>()?;

        Ok(Self(inner))
    }
}

/// The Zero-Knowledge challenge.
#[derive(PartialEq)]
pub struct Challenge(pub Scalar);

/// Holds the initial messages in the Zero-Knowledge Proofs sent by CDD Provider.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ZKPInitialmessage {
    cdd_id_proof: InitialMessage,
    cdd_id_second_half_proof: InitialMessage,
    uid_commitment_proof: InitialMessage,
    /// Committed CDD ID. Corresponding to g^uID * h^DID * f^{hash(uID, DID)}`.
    a: RistrettoPoint,
    /// Committed version of the second half CDD ID. Corresponding to (h^DID*f^{hash(uID, DID)})^r.
    b: RistrettoPoint,
}

impl Encode for ZKPInitialmessage {
    #[inline]
    fn size_hint(&self) -> usize {
        self.cdd_id_proof.size_hint()
            + self.cdd_id_second_half_proof.size_hint()
            + self.uid_commitment_proof.size_hint()
            + RistrettoPointEncoder(&self.a).size_hint()
            + RistrettoPointEncoder(&self.b).size_hint()
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.cdd_id_proof.encode_to(dest);
        self.cdd_id_second_half_proof.encode_to(dest);
        self.uid_commitment_proof.encode_to(dest);
        RistrettoPointEncoder(&self.a).encode_to(dest);
        RistrettoPointEncoder(&self.b).encode_to(dest);
    }
}

impl Decode for ZKPInitialmessage {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let cdd_id_proof = <InitialMessage>::decode(input)?;
        let cdd_id_second_half_proof = <InitialMessage>::decode(input)?;
        let uid_commitment_proof = <InitialMessage>::decode(input)?;

        let a = CompressedRistretto(<[u8; RISTRETTO_POINT_SIZE]>::decode(input)?)
            .decompress()
            .ok_or_else(|| CodecError::from("Invalid compressed `RistrettoPoint`."))?;

        let b = CompressedRistretto(<[u8; RISTRETTO_POINT_SIZE]>::decode(input)?)
            .decompress()
            .ok_or_else(|| CodecError::from("Invalid compressed `RistrettoPoint`."))?;

        Ok(Self {
            cdd_id_proof,
            cdd_id_second_half_proof,
            uid_commitment_proof,
            a,
            b,
        })
    }
}

/// Holds the CDD Provider's response to the PUIS challenge.
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ZKPFinalResponse {
    cdd_id_proof_response: FinalResponse,
    cdd_id_second_half_proof_response: FinalResponse,
    uid_commitment_proof_response: FinalResponse,
}

/// Holds PUIS secret data.
#[derive(Clone)]
pub struct VerifierSecrets {
    rand: Scalar,
}

impl Decode for VerifierSecrets {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let raw = <[u8; SCALAR_SIZE]>::decode(input)?;
        let rand = Scalar::from_bits(raw);
        Ok(Self { rand })
    }
}

impl Encode for VerifierSecrets {
    #[inline]
    fn size_hint(&self) -> usize {
        ScalarEncoder(&self.rand).size_hint()
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        ScalarEncoder(&self.rand).encode_to(dest);
    }
}

/// Modified version of `slice_to_scalar` of Confidential Identity Library.
/// Creates a scalar from a UUID.
pub fn uuid_to_scalar(uuid: Uuid) -> Scalar {
    let mut hash = [0u8; 64];
    hash.copy_from_slice(Blake2b::digest(uuid.as_bytes()).as_slice());
    cryptography_core::curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&hash).into()
}

/// Represents the first leg of the protocol from PUIS to CDD Provider.
pub trait CommittedSetGenerator {
    /// This is called by PUIS to create a committed version of the set of all the unique
    /// identity IDs (uID).
    ///
    /// # Arguments
    /// * `private_unique_identifiers`: A list of Scalars that represent the private set of
    ///   unique identifiers. Call `uuid_to_scalar` to convert uIDs to Scalar properly.
    /// * `min_set_size`: An optional parameter to override the default value of
    ///   `SET_SIZE_ANONYMITY_PARAM`.
    /// * `rng`: Cryptographically secure random number generator.
    ///
    /// # Outputs
    /// * `VerifierSecrets`: The secret values of PUIS. These are needed in later steps of
    ///    the protocol and need to be stored locally.
    /// * `CommittedUids`: The padded, committed, and shuffled set of uIDs. These should
    ///    be sent to CDD Provider.
    fn generate_committed_set<T: RngCore + CryptoRng>(
        private_unique_identifiers: PrivateUids,
        min_set_size: Option<usize>,
        rng: &mut T,
    ) -> Fallible<(VerifierSecrets, CommittedUids)>;
}

/// Represents the second leg of the protocol from CDD Provider to PUIS.
pub trait ProofGenerator {
    /// This is called by the CDD Provider in the second step of the protocol to generate
    /// the ZKP proofs that CDD Provider knows a `uID` and a `DID` such that
    ///
    /// `CDD_ID = g^uID * h^DID * f^{hash(uID, DID)}` for some pre-determined `g, h, and f`.
    ///
    /// Moreover, it proves that the uID belongs to the set of valid uIDs of PUIS.
    ///
    /// # Arguments
    /// * `claims`: Holds the list of uID and DID of the investor.
    /// * `committed_uids`: The padded, committed, and shuffled set of uIDs.
    /// * `rng`: Cryptographically secure random number generator.
    ///
    /// # Outputs
    /// * `ZKPInitialmessage`: The list of initial messages of ZKPs.
    /// * `ZKPFinalResponse`: The list of ZKP response.
    /// * `CommittedUids`: The re-committed uIDs form part of the proof of membership.
    fn generate_proofs<T: RngCore + CryptoRng>(
        claims: &[CddClaimData],
        committed_uids: &CommittedUids,
        rng: &mut T,
    ) -> Fallible<(Vec<ZKPInitialmessage>, Vec<ZKPFinalResponse>, CommittedUids)>;
}

/// Represents the last step of the protocol in which PUIS verifies the proofs.
pub trait ProofVerifier {
    /// PUIS verifies both the ZKP proofs around CDD ID and the proof of membership.
    ///
    /// # Arguments
    /// * `initial_messages`: The list of the initial messages of ZKP proofs of CDD ID.
    /// * `final_responses`: The list of the iinal responses of ZKP proofs of CDD ID.
    /// * `challenges`: The list of the ihe ZKP challenge generated by PUIS.
    /// * `cdd_ids`: The list of the ihe CDD ID read from the chain.
    /// * `verifier_secrets`: The PUIS secrets generated in the second step of the protocol.
    /// * `re_committed_uids`: The re-committed uIDs form part of the proof of membership.
    ///
    /// # Outputs
    /// * A list of results, where Ok(()) shows success in proof and Err(error) shows the failure
    ///   with the error.
    fn verify_proofs(
        initial_messages: &[ZKPInitialmessage],
        final_responses: &[ZKPFinalResponse],
        cdd_ids: &[CddId],
        verifier_secrets: &VerifierSecrets,
        re_committed_uids: &CommittedUids,
    ) -> Vec<Fallible<()>>;
}
