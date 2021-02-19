use super::cdd_claim::{RISTRETTO_POINT_SIZE, SCALAR_SIZE}; // todo: maybe move these here.
use codec::{Decode, Encode, Error as CodecError, Input, Output};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint as DalekRistrettoPoint},
    scalar::Scalar as DalekScalar,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RistrettoPoint(pub DalekRistrettoPoint);

impl Encode for RistrettoPoint {
    #[inline]
    fn size_hint(&self) -> usize {
        RISTRETTO_POINT_SIZE
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.0.compress().as_bytes().encode_to(dest);
    }
}

impl Decode for RistrettoPoint {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let id = <[u8; RISTRETTO_POINT_SIZE]>::decode(input)?;
        CompressedRistretto(id)
            .decompress()
            .ok_or_else(|| CodecError::from("Invalid RistrettoPoint."))
            .map(RistrettoPoint)
    }
}

impl From<RistrettoPoint> for DalekRistrettoPoint {
    fn from(point_data: RistrettoPoint) -> DalekRistrettoPoint {
        point_data.0
    }
}

impl From<DalekRistrettoPoint> for RistrettoPoint {
    fn from(point: DalekRistrettoPoint) -> RistrettoPoint {
        RistrettoPoint(point)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Scalar(pub DalekScalar);

impl Encode for Scalar {
    #[inline]
    fn size_hint(&self) -> usize {
        SCALAR_SIZE
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.0.as_bytes().encode_to(dest);
    }
}

impl Decode for Scalar {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let scalar = <[u8; SCALAR_SIZE]>::decode(input)?;

        Ok(Scalar(DalekScalar::from_bits(scalar)))
    }
}

impl From<Scalar> for DalekScalar {
    fn from(scalar_data: Scalar) -> DalekScalar {
        scalar_data.0
    }
}

impl From<DalekScalar> for Scalar {
    fn from(scalar: DalekScalar) -> Scalar {
        Scalar(scalar)
    }
}
