//! Shared protocol library for the decentralised web.
//!
//! Everything that two independent implementations must agree on lives here:
//! the network config (`network.toml`), name rules, the canonical byte
//! encoding of operations, signatures, proof-of-work, and the deterministic
//! ledger state machine that turns a set of operations into name records.
//!
//! The wire format is described in `docs/SPEC.md`.

pub mod config;
pub mod crypto;
pub mod encoding;
pub mod error;
pub mod ledger;
pub mod name;
pub mod op;
pub mod pow;

pub use config::NetworkConfig;
pub use crypto::{Hash, PublicKey, SecretKey, Signature};
pub use error::{Error, Result};
pub use ledger::{Ledger, NameRecord, OpStatus};
pub use op::{Op, OpBody, Target};

/// Protocol version, mixed into every domain-separation tag.
pub const PROTOCOL_VERSION: &str = "dweb1";

/// Current unix time in seconds.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
