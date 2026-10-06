//! Ledger operations. Every change to the registry is one of these, signed by
//! the key allowed to make it and carrying proof-of-work.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::config::NetworkConfig;
use crate::crypto::{Hash, PublicKey, SecretKey, Signature, tagged_hash};
use crate::encoding::Writer;
use crate::error::{Error, Result};
use crate::name;
use crate::pow;

/// Where a name's site lives and which key the site server proves it holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// Public key the site server presents in its TLS certificate. The
    /// resolver refuses to load the site unless the server proves it holds
    /// the matching private key. Kept separate from the owner key so the owner
    /// key can stay offline.
    #[serde(default)]
    pub site_key: Option<PublicKey>,
    /// `ip:port`, `[ipv6]:port`, `something.onion:port` or `something.i2p:port`.
    #[serde(default)]
    pub address: Option<String>,
}

impl Target {
    pub fn validate(&self) -> Result<()> {
        if let Some(k) = &self.site_key {
            k.validate()?;
        }
        if let Some(a) = &self.address {
            validate_address(a)?;
        }
        Ok(())
    }

    fn encode(&self, w: &mut Writer) -> Result<()> {
        w.opt_fixed(self.site_key.as_ref().map(|k| &k.0[..]));
        w.opt_str(self.address.as_deref())?;
        Ok(())
    }
}

/// Checks a server address: an IP address or an onion / I2P host, with a port.
pub fn validate_address(addr: &str) -> Result<()> {
    let bad = |why: &str| Error::Op(format!("bad address {addr:?}: {why}"));
    if addr.len() > 255 {
        return Err(bad("too long"));
    }
    let (host, port) = addr.rsplit_once(':').ok_or_else(|| bad("missing :port"))?;
    let port: u16 = port.parse().map_err(|_| bad("bad port"))?;
    if port == 0 {
        return Err(bad("port 0"));
    }
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return v6
            .parse::<std::net::Ipv6Addr>()
            .map(|_| ())
            .map_err(|_| bad("bad IPv6 address"));
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let overlay = host.ends_with(".onion") || host.ends_with(".i2p");
    let chars_ok = host
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-');
    if overlay && chars_ok {
        Ok(())
    } else {
        Err(bad(
            "host must be an IP address or an .onion / .i2p address",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum OpBody {
    /// Step one of registration: a hidden hash of the name and owner.
    Commit { commitment: Hash },
    /// Step two: reveals the name behind an earlier commit and claims it.
    Reveal {
        commit: Hash,
        name: String,
        owner: PublicKey,
        salt: Hash,
        #[serde(default)]
        target: Target,
    },
    /// A free name minted by the genesis key, without registration work.
    Mint {
        name: String,
        owner: PublicKey,
        #[serde(default)]
        target: Target,
    },
    /// Owner changes where the name points.
    Update {
        name: String,
        seq: u64,
        target: Target,
    },
    /// Owner extends the expiry.
    Renew { name: String, seq: u64 },
    /// Owner hands the name to a new key.
    Transfer {
        name: String,
        seq: u64,
        new_owner: PublicKey,
    },
}

impl OpBody {
    pub fn kind(&self) -> &'static str {
        match self {
            OpBody::Commit { .. } => "commit",
            OpBody::Reveal { .. } => "reveal",
            OpBody::Mint { .. } => "mint",
            OpBody::Update { .. } => "update",
            OpBody::Renew { .. } => "renew",
            OpBody::Transfer { .. } => "transfer",
        }
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            OpBody::Commit { .. } => None,
            OpBody::Reveal { name, .. }
            | OpBody::Mint { name, .. }
            | OpBody::Update { name, .. }
            | OpBody::Renew { name, .. }
            | OpBody::Transfer { name, .. } => Some(name),
        }
    }

    /// Proof-of-work bits an operation with this body needs.
    pub fn pow_bits(&self, cfg: &NetworkConfig) -> u32 {
        let p = &cfg.pow_curve;
        match self {
            OpBody::Commit { .. } => p.commit_bits.max(p.op_bits),
            OpBody::Reveal { name, .. } => cfg.name_pow_bits(name),
            _ => p.op_bits,
        }
    }

    fn encode(&self, w: &mut Writer) -> Result<()> {
        match self {
            OpBody::Commit { commitment } => {
                w.u8(1).fixed(&commitment.0);
            }
            OpBody::Reveal {
                commit,
                name,
                owner,
                salt,
                target,
            } => {
                w.u8(2)
                    .fixed(&commit.0)
                    .str(name)?
                    .fixed(&owner.0)
                    .fixed(&salt.0);
                target.encode(w)?;
            }
            OpBody::Mint {
                name,
                owner,
                target,
            } => {
                w.u8(3).str(name)?.fixed(&owner.0);
                target.encode(w)?;
            }
            OpBody::Update { name, seq, target } => {
                w.u8(4).str(name)?.u64(*seq);
                target.encode(w)?;
            }
            OpBody::Renew { name, seq } => {
                w.u8(5).str(name)?.u64(*seq);
            }
            OpBody::Transfer {
                name,
                seq,
                new_owner,
            } => {
                w.u8(6).str(name)?.u64(*seq).fixed(&new_owner.0);
            }
        }
        Ok(())
    }
}

/// The hidden value published in a commit.
pub fn commitment(network: &Hash, name: &str, owner: &PublicKey, salt: &Hash) -> Hash {
    let mut w = Writer::new();
    w.fixed(&network.0);
    w.str(name).expect("names are short");
    w.fixed(&owner.0).fixed(&salt.0);
    tagged_hash("commitment", &[&w.finish()])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Op {
    /// Network ID; operations from another network are rejected.
    pub network: Hash,
    /// Unix seconds when the operation was made.
    pub timestamp: u64,
    pub body: OpBody,
    /// Key that signed the operation. Every kind except `commit` is signed.
    #[serde(default)]
    pub signer: Option<PublicKey>,
    /// Proof-of-work nonce.
    pub nonce: u64,
    #[serde(default)]
    pub signature: Option<Signature>,
}

impl Op {
    /// The bytes covered by proof-of-work and the signature.
    pub fn signed_bytes(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.fixed(&self.network.0).u64(self.timestamp);
        self.body.encode(&mut w)?;
        w.opt_fixed(self.signer.as_ref().map(|k| &k.0[..]));
        w.u64(self.nonce);
        Ok(w.finish())
    }

    fn signing_message(signed_bytes: &[u8]) -> Vec<u8> {
        let mut m = format!("{}/sign\0", crate::PROTOCOL_VERSION).into_bytes();
        m.extend_from_slice(signed_bytes);
        m
    }

    pub fn pow_hash(&self) -> Result<Hash> {
        Ok(tagged_hash("pow", &[&self.signed_bytes()?]))
    }

    /// Unique ID of the operation, covering the signature too.
    pub fn id(&self) -> Hash {
        let bytes = self.signed_bytes().unwrap_or_default();
        let sig = self.signature.map(|s| s.0.to_vec()).unwrap_or_default();
        tagged_hash("op-id", &[&bytes, &sig])
    }

    /// Proof-of-work bits this operation needs.
    pub fn required_bits(&self, cfg: &NetworkConfig) -> u32 {
        self.body.pow_bits(cfg)
    }

    /// Builds an operation, does the proof-of-work and signs it.
    pub fn create(
        cfg: &NetworkConfig,
        timestamp: u64,
        body: OpBody,
        key: Option<&SecretKey>,
    ) -> Result<Op> {
        let mut op = Op {
            network: cfg.network_id(),
            timestamp,
            body,
            signer: key.map(SecretKey::public),
            nonce: 0,
            signature: None,
        };
        let bits = op.required_bits(cfg);
        let mut prefix = op.signed_bytes()?;
        prefix.truncate(prefix.len() - 8);
        op.nonce = pow::solve(bits, |n| tagged_hash("pow", &[&prefix, &n.to_be_bytes()]));
        if let Some(k) = key {
            let msg = Self::signing_message(&op.signed_bytes()?);
            op.signature = Some(k.sign(&msg));
        }
        Ok(op)
    }

    /// Every check that does not depend on ledger state. Nodes reject any
    /// operation that fails these before storing or relaying it.
    pub fn check_stateless(&self, cfg: &NetworkConfig, network_id: &Hash) -> Result<()> {
        if &self.network != network_id {
            return Err(Error::Op("operation is for a different network".into()));
        }
        if let Some(n) = self.body.name() {
            let norm = name::normalize(n, &cfg.name_rules)?;
            if norm != n {
                return Err(Error::Op(format!("name {n:?} is not in normal form")));
            }
        }
        match &self.body {
            OpBody::Reveal { target, owner, .. } | OpBody::Mint { target, owner, .. } => {
                target.validate()?;
                owner.validate()?;
            }
            OpBody::Update { target, .. } => target.validate()?,
            OpBody::Transfer { new_owner, .. } => new_owner.validate()?,
            _ => {}
        }
        let bytes = self.signed_bytes()?;
        if bytes.len() > 4096 {
            return Err(Error::Op("operation too large".into()));
        }
        let bits = self.required_bits(cfg);
        if tagged_hash("pow", &[&bytes]).leading_zero_bits() < bits {
            return Err(Error::Op(format!(
                "not enough proof-of-work (need {bits} bits)"
            )));
        }
        match (&self.body, &self.signer, &self.signature) {
            (OpBody::Commit { .. }, None, None) => return Ok(()),
            (OpBody::Commit { .. }, _, _) => {
                return Err(Error::Op("commits must not be signed".into()));
            }
            (_, Some(signer), Some(sig)) => {
                signer.verify(&Self::signing_message(&bytes), sig)?;
            }
            _ => return Err(Error::Op("operation must be signed".into())),
        }
        let signer = self.signer.expect("checked above");
        match &self.body {
            OpBody::Reveal { owner, .. } if *owner != signer => {
                Err(Error::Op("reveal must be signed by the new owner".into()))
            }
            OpBody::Mint { .. } => match cfg.genesis_public_key()? {
                None => Err(Error::Op("this network has no genesis key".into())),
                Some(g) if g != signer => {
                    Err(Error::Op("mint must be signed by the genesis key".into()))
                }
                Some(_) => Ok(()),
            },
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_config;

    #[test]
    fn create_and_check() {
        let cfg = test_config();
        let id = cfg.network_id();
        let sk = SecretKey::generate().unwrap();
        let op = Op::create(
            &cfg,
            1000,
            OpBody::Renew {
                name: "alice.xyz".into(),
                seq: 1,
            },
            Some(&sk),
        )
        .unwrap();
        op.check_stateless(&cfg, &id).unwrap();

        let mut tampered = op.clone();
        tampered.timestamp += 1;
        assert!(tampered.check_stateless(&cfg, &id).is_err());

        let mut other = cfg.clone();
        other.network_name = "fork".into();
        assert!(op.check_stateless(&other, &other.network_id()).is_err());
    }

    #[test]
    fn json_roundtrip_keeps_id() {
        let cfg = test_config();
        let op = Op::create(
            &cfg,
            5,
            OpBody::Commit {
                commitment: Hash([7; 32]),
            },
            None,
        )
        .unwrap();
        let json = serde_json::to_string(&op).unwrap();
        let back: Op = serde_json::from_str(&json).unwrap();
        assert_eq!(op.id(), back.id());
        back.check_stateless(&cfg, &cfg.network_id()).unwrap();
    }

    #[test]
    fn addresses() {
        for ok in [
            "1.2.3.4:443",
            "[::1]:8443",
            "abcdefg.onion:443",
            "x-y.b32.i2p:80",
        ] {
            validate_address(ok).unwrap();
        }
        for bad in [
            "1.2.3.4",
            "example.com:443",
            "1.2.3.4:0",
            "[zz]:1",
            "a.onion:x",
        ] {
            assert!(validate_address(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn non_normal_names_rejected() {
        let cfg = test_config();
        let sk = SecretKey::generate().unwrap();
        let op = Op::create(
            &cfg,
            1,
            OpBody::Renew {
                name: "Alice.xyz".into(),
                seq: 1,
            },
            Some(&sk),
        )
        .unwrap();
        assert!(op.check_stateless(&cfg, &cfg.network_id()).is_err());
    }
}
