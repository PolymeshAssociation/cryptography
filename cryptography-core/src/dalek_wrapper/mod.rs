use super::cdd_claim::{RISTRETTO_POINT_SIZE, SCALAR_SIZE}; // todo: maybe move these here.
use codec::{Decode, Encode, Error as CodecError, Input, Output};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PointData(pub RistrettoPoint);

impl Encode for PointData {
    #[inline]
    fn size_hint(&self) -> usize {
        RISTRETTO_POINT_SIZE
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.0.compress().as_bytes().encode_to(dest);
    }
}

impl Decode for PointData {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let id = <[u8; RISTRETTO_POINT_SIZE]>::decode(input)?;
        CompressedRistretto(id)
            .decompress()
            .ok_or_else(|| CodecError::from("Invalid PointData."))
            .map(PointData)
    }
}

impl From<PointData> for RistrettoPoint {
    fn from(point_data: PointData) -> RistrettoPoint {
        point_data.0
    }
}

impl From<RistrettoPoint> for PointData {
    fn from(point: RistrettoPoint) -> PointData {
        PointData(point)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ScalarData(pub Scalar);

impl Encode for ScalarData {
    #[inline]
    fn size_hint(&self) -> usize {
        SCALAR_SIZE
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.0.as_bytes().encode_to(dest);
    }
}

impl Decode for ScalarData {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let scalar = <[u8; SCALAR_SIZE]>::decode(input)?;

        Ok(ScalarData(Scalar::from_bits(scalar)))
    }
}

impl From<ScalarData> for Scalar {
    fn from(scalar_data: ScalarData) -> Scalar {
        scalar_data.0
    }
}

impl From<Scalar> for ScalarData {
    fn from(scalar: Scalar) -> ScalarData {
        ScalarData(scalar)
    }
}
