//! `network.toml`: every network-specific choice lives in this one file.
//!
//! Forking the network means editing this file and nothing else. The
//! consensus-relevant fields are hashed into the network ID, which is mixed
//! into every signature, proof-of-work and message, so two networks with
//! different configs can never accept each other's operations.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto::{Hash, PublicKey, tagged_hash};
use crate::encoding::Writer;
use crate::error::{Error, Result};

const SECS_PER_DAY: u64 = 86_400;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Human name of the network. Part of the network ID.
    pub network_name: String,

    /// Hex public key allowed to mint free names, or empty for none.
    #[serde(default)]
    pub genesis_key: String,

    /// Maximum number of free (admin-minted) names.
    #[serde(default)]
    pub genesis_cap: u64,

    /// Optional taper: after `after_days` days from launch, the total cap
    /// becomes `cap`. Use it to lower (or freeze) the allowance over time.
    #[serde(default)]
    pub genesis_schedule: Vec<CapStep>,

    /// Unix time the network launched. The taper schedule counts from here.
    #[serde(default)]
    pub launch_time: u64,

    /// How long a name lasts before it must be renewed.
    #[serde(default = "default_expiry_days")]
    pub expiry_days: u64,

    #[serde(default)]
    pub pow_curve: PowCurve,

    #[serde(default)]
    pub name_rules: NameRules,

    #[serde(default)]
    pub registration: RegistrationRules,

    /// Registry nodes new peers connect to first (`http://host:port`).
    #[serde(default)]
    pub bootstrap_nodes: Vec<String>,

    /// How resolvers, wallets and nodes reach the network.
    #[serde(default)]
    pub transport: Transport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapStep {
    pub after_days: u64,
    pub cap: u64,
}

/// Proof-of-work cost curve. Difficulty is a number of leading zero bits in
/// a SHA-256 hash; each extra bit doubles the expected work.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowCurve {
    /// Minimum work on every operation, to stop ledger spam.
    pub op_bits: u32,
    /// Work on a commit (the hidden first step of registration).
    pub commit_bits: u32,
    /// Work to register a name of `short_name_length` characters or more.
    pub base_bits: u32,
    /// Names shorter than this cost more.
    pub short_name_length: u32,
    /// Extra bits for each character below `short_name_length`.
    pub extra_bits_per_char: u32,
    /// Exact overrides by name length, e.g. `{ "1" = 40, "2" = 36 }`.
    #[serde(default)]
    pub length_bits: BTreeMap<String, u32>,
}

impl Default for PowCurve {
    fn default() -> Self {
        Self {
            op_bits: 8,
            commit_bits: 12,
            base_bits: 22,
            short_name_length: 8,
            extra_bits_per_char: 2,
            length_bits: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameRules {
    pub min_length: u32,
    pub max_length: u32,
    /// Every character a name may contain. Names are lower-cased first.
    pub allowed_chars: String,
}

impl Default for NameRules {
    fn default() -> Self {
        Self {
            min_length: 1,
            max_length: 63,
            allowed_chars: "abcdefghijklmnopqrstuvwxyz0123456789-.".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRules {
    /// A reveal must come at least this long after its commit. Must be larger
    /// than `max_clock_skew_secs`, or a watcher could back-date a commit and
    /// steal a name they saw revealed.
    pub reveal_min_delay_secs: u64,
    /// A reveal must come within this long of its commit. This is also the
    /// window in which an earlier commit can still win a contested name.
    pub reveal_window_secs: u64,
    /// How far an operation's timestamp may differ from a node's clock when
    /// the node first sees it.
    pub max_clock_skew_secs: u64,
}

impl Default for RegistrationRules {
    fn default() -> Self {
        Self {
            reveal_min_delay_secs: 600,
            reveal_window_secs: 86_400,
            max_clock_skew_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Transport {
    /// `direct`, `tor` or `i2p`.
    #[serde(default)]
    pub mode: TransportMode,
    /// SOCKS5 proxy for `tor` (default 127.0.0.1:9050) or `i2p`
    /// (default 127.0.0.1:4447).
    #[serde(default)]
    pub socks_proxy: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransportMode {
    #[default]
    Direct,
    Tor,
    I2p,
}

impl Transport {
    /// The SOCKS5 proxy to use, if any.
    pub fn socks_proxy(&self) -> Option<String> {
        match self.mode {
            TransportMode::Direct => self.socks_proxy.clone(),
            TransportMode::Tor => Some(
                self.socks_proxy
                    .clone()
                    .unwrap_or_else(|| "127.0.0.1:9050".into()),
            ),
            TransportMode::I2p => Some(
                self.socks_proxy
                    .clone()
                    .unwrap_or_else(|| "127.0.0.1:4447".into()),
            ),
        }
    }
}

fn default_expiry_days() -> u64 {
    365
}

impl NetworkConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let cfg: NetworkConfig = toml::from_str(text).map_err(|e| Error::Config(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.network_name.trim().is_empty() {
            return Err(Error::Config("network_name must not be empty".into()));
        }
        self.genesis_public_key()?;
        if self.expiry_days == 0 {
            return Err(Error::Config("expiry_days must be at least 1".into()));
        }
        let r = &self.registration;
        if r.reveal_min_delay_secs <= r.max_clock_skew_secs {
            return Err(Error::Config(
                "registration.reveal_min_delay_secs must be greater than max_clock_skew_secs"
                    .into(),
            ));
        }
        if r.reveal_window_secs <= r.reveal_min_delay_secs {
            return Err(Error::Config(
                "registration.reveal_window_secs must be greater than reveal_min_delay_secs".into(),
            ));
        }
        let n = &self.name_rules;
        if n.min_length == 0 || n.min_length > n.max_length || n.max_length > 253 {
            return Err(Error::Config(
                "name_rules: need 1 <= min_length <= max_length <= 253".into(),
            ));
        }
        if n.allowed_chars.is_empty() {
            return Err(Error::Config("name_rules.allowed_chars is empty".into()));
        }
        for c in n.allowed_chars.chars() {
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.') {
                return Err(Error::Config(format!(
                    "name_rules.allowed_chars may only contain a-z, 0-9, '-' and '.' \
                     (names must be valid host names), found {c:?}"
                )));
            }
        }
        for k in self.pow_curve.length_bits.keys() {
            k.parse::<u32>().map_err(|_| {
                Error::Config(format!("pow_curve.length_bits key {k:?} is not a number"))
            })?;
        }
        let max_bits = [
            self.pow_curve.op_bits,
            self.pow_curve.commit_bits,
            self.pow_curve.base_bits,
        ]
        .into_iter()
        .chain(self.pow_curve.length_bits.values().copied())
        .max()
        .unwrap_or(0);
        if max_bits > 64 {
            return Err(Error::Config("pow_curve: difficulty above 64 bits".into()));
        }
        Ok(())
    }

    pub fn genesis_public_key(&self) -> Result<Option<PublicKey>> {
        let k = self.genesis_key.trim();
        if k.is_empty() {
            return Ok(None);
        }
        let pk = PublicKey::from_hex(k).map_err(|e| Error::Config(format!("genesis_key: {e}")))?;
        pk.validate()
            .map_err(|e| Error::Config(format!("genesis_key: {e}")))?;
        Ok(Some(pk))
    }

    /// Total free names the genesis key may have minted by time `t`.
    pub fn genesis_cap_at(&self, t: u64) -> u64 {
        let days = t.saturating_sub(self.launch_time) / SECS_PER_DAY;
        let mut cap = self.genesis_cap;
        let mut steps = self.genesis_schedule.clone();
        steps.sort_by_key(|s| s.after_days);
        for s in steps {
            if days >= s.after_days {
                cap = s.cap;
            }
        }
        cap
    }

    pub fn expiry_secs(&self) -> u64 {
        self.expiry_days.saturating_mul(SECS_PER_DAY)
    }

    /// Proof-of-work bits needed to register `name`.
    pub fn name_pow_bits(&self, name: &str) -> u32 {
        let len = name.chars().count() as u32;
        let p = &self.pow_curve;
        if let Some(b) = p.length_bits.get(&len.to_string()) {
            return (*b).max(p.op_bits);
        }
        let short_by = p.short_name_length.saturating_sub(len);
        (p.base_bits + short_by * p.extra_bits_per_char).max(p.op_bits)
    }

    /// The network ID: a hash of every consensus-relevant setting.
    ///
    /// `bootstrap_nodes` and `transport` are local choices and are left out.
    pub fn network_id(&self) -> Hash {
        let mut w = Writer::new();
        let enc = (|| -> Result<()> {
            w.str(&self.network_name)?;
            let gk = self.genesis_public_key()?;
            w.opt_fixed(gk.as_ref().map(|k| &k.0[..]));
            w.u64(self.genesis_cap);
            let mut steps = self.genesis_schedule.clone();
            steps.sort_by_key(|s| s.after_days);
            w.u64(steps.len() as u64);
            for s in &steps {
                w.u64(s.after_days).u64(s.cap);
            }
            w.u64(self.launch_time);
            w.u64(self.expiry_days);
            let p = &self.pow_curve;
            w.u64(p.op_bits as u64)
                .u64(p.commit_bits as u64)
                .u64(p.base_bits as u64)
                .u64(p.short_name_length as u64)
                .u64(p.extra_bits_per_char as u64);
            let mut lb: Vec<(u32, u32)> = p
                .length_bits
                .iter()
                .filter_map(|(k, v)| k.parse().ok().map(|k| (k, *v)))
                .collect();
            lb.sort();
            w.u64(lb.len() as u64);
            for (k, v) in lb {
                w.u64(k as u64).u64(v as u64);
            }
            let n = &self.name_rules;
            w.u64(n.min_length as u64).u64(n.max_length as u64);
            w.str(&n.allowed_chars)?;
            let r = &self.registration;
            w.u64(r.reveal_min_delay_secs)
                .u64(r.reveal_window_secs)
                .u64(r.max_clock_skew_secs);
            Ok(())
        })();
        // validate() has already run on any loaded config, so this cannot fail.
        enc.expect("network config encodes");
        tagged_hash("network-id", &[&w.finish()])
    }
}

#[cfg(test)]
pub(crate) fn test_config() -> NetworkConfig {
    NetworkConfig::parse(
        r#"
network_name = "testnet"
genesis_cap = 2
expiry_days = 1

[pow_curve]
op_bits = 1
commit_bits = 2
base_bits = 3
short_name_length = 4
extra_bits_per_char = 1

[registration]
reveal_min_delay_secs = 10
reveal_window_secs = 100
max_clock_skew_secs = 5
"#,
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses() {
        let text = include_str!("../../../network.toml");
        let cfg = NetworkConfig::parse(text).unwrap();
        assert_eq!(cfg.network_name, "mynet");
    }

    #[test]
    fn network_id_changes_with_consensus_fields_only() {
        let a = test_config();
        let mut b = a.clone();
        b.bootstrap_nodes.push("http://example:7700".into());
        assert_eq!(a.network_id(), b.network_id());
        b.network_name = "othernet".into();
        assert_ne!(a.network_id(), b.network_id());
    }

    #[test]
    fn pow_curve() {
        let cfg = test_config();
        assert_eq!(cfg.name_pow_bits("abcdef"), 3);
        assert_eq!(cfg.name_pow_bits("ab"), 5);
        let mut cfg = cfg;
        cfg.pow_curve.length_bits.insert("1".into(), 9);
        assert_eq!(cfg.name_pow_bits("a"), 9);
    }

    #[test]
    fn genesis_taper() {
        let mut cfg = test_config();
        cfg.launch_time = 1000;
        cfg.genesis_cap = 100;
        cfg.genesis_schedule = vec![
            CapStep {
                after_days: 30,
                cap: 50,
            },
            CapStep {
                after_days: 10,
                cap: 80,
            },
        ];
        assert_eq!(cfg.genesis_cap_at(1000), 100);
        assert_eq!(cfg.genesis_cap_at(1000 + 10 * SECS_PER_DAY), 80);
        assert_eq!(cfg.genesis_cap_at(1000 + 31 * SECS_PER_DAY), 50);
    }

    #[test]
    fn rejects_unsafe_reveal_delay() {
        let mut cfg = test_config();
        cfg.registration.reveal_min_delay_secs = 5;
        assert!(cfg.validate().is_err());
    }
}
