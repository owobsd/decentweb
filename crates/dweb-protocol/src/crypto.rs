//! Keys, signatures and hashes. Ed25519 for signatures, SHA-256 for hashes.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

macro_rules! hex_bytes {
    ($name:ident, $len:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }
            pub fn from_hex(s: &str) -> Result<Self> {
                let v =
                    hex::decode(s.trim()).map_err(|e| Error::Encoding(format!("bad hex: {e}")))?;
                let arr: [u8; $len] = v
                    .try_into()
                    .map_err(|_| Error::Encoding(format!("expected {} bytes", $len)))?;
                Ok(Self(arr))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self> {
                Self::from_hex(s)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::from_hex(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

hex_bytes!(Hash, 32);
hex_bytes!(PublicKey, 32);
hex_bytes!(Signature, 64);

impl Default for Hash {
    fn default() -> Self {
        Hash::ZERO
    }
}

impl Hash {
    pub const ZERO: Hash = Hash([0u8; 32]);

    /// Number of leading zero bits, used for proof-of-work.
    pub fn leading_zero_bits(&self) -> u32 {
        let mut n = 0;
        for b in self.0 {
            if b == 0 {
                n += 8;
            } else {
                n += b.leading_zeros();
                break;
            }
        }
        n
    }
}

/// SHA-256 over a domain-separation tag followed by the given parts.
///
/// The tag is written as `"dweb1/" + tag + 0x00` so different uses of the
/// hash can never collide.
pub fn tagged_hash(tag: &str, parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update(crate::PROTOCOL_VERSION.as_bytes());
    h.update(b"/");
    h.update(tag.as_bytes());
    h.update([0u8]);
    for p in parts {
        h.update(p);
    }
    Hash(h.finalize().into())
}

impl PublicKey {
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.0)
            .map_err(|e| Error::Crypto(format!("bad public key: {e}")))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
        vk.verify_strict(msg, &sig)
            .map_err(|_| Error::Crypto("signature does not verify".into()))
    }

    /// Checks that the bytes are a valid Ed25519 point.
    pub fn validate(&self) -> Result<()> {
        VerifyingKey::from_bytes(&self.0)
            .map(|_| ())
            .map_err(|e| Error::Crypto(format!("bad public key: {e}")))
    }
}

/// An Ed25519 private key. Whoever holds this owns the names bound to it.
#[derive(Clone)]
pub struct SecretKey(SigningKey);

impl SecretKey {
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| Error::Crypto(format!("no randomness: {e}")))?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    pub fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg).to_bytes())
    }

    /// PKCS#8 DER encoding, used to build TLS certificates from site keys.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        self.0
            .to_pkcs8_der()
            .map(|d| d.as_bytes().to_vec())
            .map_err(|e| Error::Crypto(format!("pkcs8: {e}")))
    }

    /// Key file format: hex-encoded 32-byte seed on one line.
    pub fn to_file_string(&self) -> String {
        format!("{}\n", hex::encode(self.seed()))
    }

    pub fn from_file_string(s: &str) -> Result<Self> {
        let line = s
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .ok_or_else(|| Error::Crypto("empty key file".into()))?;
        let v = hex::decode(line).map_err(|e| Error::Crypto(format!("bad key file: {e}")))?;
        let seed: [u8; 32] = v
            .try_into()
            .map_err(|_| Error::Crypto("key file must hold a 32-byte hex seed".into()))?;
        Ok(Self::from_seed(seed))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey(public={})", self.public())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SecretKey::generate().unwrap();
        let sig = sk.sign(b"hello");
        sk.public().verify(b"hello", &sig).unwrap();
        assert!(sk.public().verify(b"hullo", &sig).is_err());
    }

    #[test]
    fn key_file_roundtrip() {
        let sk = SecretKey::generate().unwrap();
        let back = SecretKey::from_file_string(&sk.to_file_string()).unwrap();
        assert_eq!(sk.public(), back.public());
    }

    #[test]
    fn leading_zeros() {
        let mut h = Hash::ZERO;
        assert_eq!(h.leading_zero_bits(), 256);
        h.0[1] = 0b0001_0000;
        assert_eq!(h.leading_zero_bits(), 11);
    }
}
