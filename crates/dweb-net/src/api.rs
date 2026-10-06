//! JSON types of the registry HTTP API. See `docs/SPEC.md` "Registry API".

use dweb_protocol::{Hash, NameRecord, Op, OpStatus};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    pub network_name: String,
    pub network_id: Hash,
    /// Random per-process ID, so a node can recognise itself in a peer list.
    pub node_id: String,
    pub ops: usize,
    pub active_names: usize,
    pub admin_minted: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitResponse {
    pub id: Hash,
    /// False if the node already had this operation.
    pub new: bool,
    pub status: Option<OpStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsPage {
    pub ops: Vec<Op>,
    /// Index to pass as `from` for the next page.
    pub next: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpInfo {
    pub op: Op,
    pub status: Option<OpStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameInfo {
    pub record: NameRecord,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}
