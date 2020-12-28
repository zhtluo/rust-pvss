use ark_bls12_381::Bls12_381;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, FromBytes, ToBytes, Zero};
use ark_std::UniformRand;
use std::ops::Add;
use std::ops::Mul;
use std::ops::Sub;
use rand::{SeedableRng, rngs::StdRng};
use ::cp::sha2::Sha256;
use ::cp::digest::Digest;

type Group381 = <Bls12_381 as PairingEngine>::G1Projective;
type Affine381 = <Bls12_381 as PairingEngine>::G1Affine;
type BigInt381 = <Bls12_381 as PairingEngine>::Fr;

pub struct Scalar {
    bn: BigInt381,
}

pub struct Point {
    point: Group381,
}

#[derive(PartialEq)]
pub struct PrivateKey {
    pub scalar: Scalar,
}

#[derive(PartialEq)]
pub struct PublicKey {
    pub point: Point,
}

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> PublicKey {
        PublicKey {
            point: Point {
                point: Affine381::read(bytes).expect("Could not create PublicKey from bytes").into_projective(),
            },
        }
    }
}

impl PrivateKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.scalar.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> PrivateKey {
        PrivateKey {
            scalar: Scalar {
                bn: BigInt381::read(bytes).expect("Could not create PublicKey from bytes"),
            },
        }
    }
}

pub fn create_keypair() -> (PublicKey, PrivateKey) {
    let s = Scalar::generate();
    let p = Point::from_scalar(&s);
    (PublicKey { point: p }, PrivateKey { scalar: s })
}

fn get_point_at_infinity() -> Group381 {
    Group381::zero()
}

fn curve_generator() -> Group381 {
    Group381::rand(&mut StdRng::seed_from_u64(42))
}

impl Scalar {
    pub fn from_u32(v: u32) -> Scalar {
        Scalar {
            bn: BigInt381::from(v),
        }
    }

    pub fn generate() -> Scalar {
        Scalar {
            bn: BigInt381::rand(&mut StdRng::from_entropy()),
        }
    }

    pub fn multiplicative_identity() -> Scalar {
        Self::from_u32(1)
    }

    pub fn hash_points(points: Vec<Point>) -> Scalar {
        let mut data = Vec::new();
        for p in points {
            data.extend_from_slice(p.to_bytes().as_slice());
        }
        let mut hasher = Sha256::new();
        hasher.input(data.as_slice());
        let mut dig: [u8; 32] = [0; 32];
        hasher.result(&mut dig);
        Scalar {
            bn: BigInt381::rand(&mut StdRng::from_seed(dig)),
        }
    }

    pub fn pow(&self, pow: u32) -> Scalar {
        Scalar {
            bn: self.bn.pow([pow as u64]),
        }
    }

    pub fn inverse(&self) -> Scalar {
        Scalar {
            bn: self.bn.inverse().expect("Inverse failure"),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        self.bn.write(&mut buf).expect("");
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Scalar {
            bn: BigInt381::read(bytes).expect("Could not create PublicKey from bytes"),
        }
    }
}

impl Clone for Scalar {
    fn clone(&self) -> Scalar {
        Scalar {
            bn: self.bn.clone(),
        }
    }
}

impl Add for Scalar {
    type Output = Self;
    fn add(self, s: Self) -> Self {
        Scalar { bn: self.bn + s.bn }
    }
}

impl Sub for Scalar {
    type Output = Self;
    fn sub(self, s: Self) -> Self {
        Scalar { bn: self.bn - s.bn }
    }
}

impl Mul for Scalar {
    type Output = Self;
    fn mul(self, s: Self) -> Self {
        Scalar { bn: self.bn * s.bn }
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.bn == other.bn
    }
}

impl Point {
    pub fn infinity() -> Point {
        Point {
            point: get_point_at_infinity(),
        }
    }

    pub fn generator() -> Point {
        Point {
            point: curve_generator(),
        }
    }

    pub fn from_scalar(s: &Scalar) -> Point {
        let gen = curve_generator();
        let p = gen.into_affine().mul(s.bn);
        Point { point: p }
    }

    pub fn mul(&self, s: &Scalar) -> Point {
        Point {
            point: self.point.into_affine().mul(s.bn),
        }
    }

    pub fn inverse(&self) -> Point {
        Point { point: -self.point }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        self.point.into_affine().write(&mut buf).expect("");
        buf
    }
}

impl Clone for Point {
    fn clone(&self) -> Point {
        Point {
            point: self.point.clone(),
        }
    }
}

impl Add for Point {
    type Output = Self;
    fn add(self, p: Self) -> Self {
        Point {
            point:self.point + p.point, 
        }
    }
}

impl Sub for Point {
    type Output = Self;
    fn sub(self, p: Self) -> Self {
        Point {
            point:self.point - p.point, 
        }
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        self.point.into_affine() == other.point.into_affine()
    }
}
