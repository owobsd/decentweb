//! Pull-based replication: every node and resolver repeatedly asks its peers
//! for operations it has not seen yet. Because ledger state is a pure
//! function of the operation set, this is all the coordination needed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use dweb_protocol::now_secs;

use crate::client::RegistryClient;
use crate::store::{Origin, Store};

const PAGE: usize = 500;

pub struct Syncer {
    store: Arc<Store>,
    client: RegistryClient,
    peers: Vec<String>,
    /// Our own node ID, to skip ourselves if listed as a peer.
    self_id: Option<String>,
    cursors: HashMap<String, usize>,
}

impl Syncer {
    pub fn new(
        store: Arc<Store>,
        client: RegistryClient,
        peers: Vec<String>,
        self_id: Option<String>,
    ) -> Self {
        let mut peers: Vec<String> = peers
            .into_iter()
            .map(|p| p.trim_end_matches('/').to_string())
            .collect();
        peers.sort();
        peers.dedup();
        Self {
            store,
            client,
            peers,
            self_id,
            cursors: HashMap::new(),
        }
    }

    pub fn peers(&self) -> &[String] {
        &self.peers
    }

    /// Fetches everything new from one peer. Returns the number of new ops.
    async fn sync_peer(&mut self, peer: &str) -> Result<usize> {
        let info = self.client.info(peer).await?;
        if info.network_id != self.store.network_id() {
            bail!("peer is on a different network ({})", info.network_name);
        }
        if Some(&info.node_id) == self.self_id.as_ref() {
            bail!("peer is this node");
        }
        let mut from = *self.cursors.get(peer).unwrap_or(&0);
        if info.ops < from {
            from = 0; // peer lost or reordered its log; start over
        }
        let mut added = 0;
        loop {
            let page = self.client.ops(peer, from, PAGE).await?;
            if page.ops.is_empty() {
                break;
            }
            let n = page.ops.len();
            for r in self.store.add_many(page.ops, Origin::Peer, now_secs()) {
                match r {
                    Ok((_, true)) => added += 1,
                    Ok((_, false)) => {}
                    Err(e) => tracing::debug!("refused op from {peer}: {e}"),
                }
            }
            from = page.next;
            self.cursors.insert(peer.to_string(), from);
            if n < PAGE {
                break;
            }
        }
        Ok(added)
    }

    /// One pass over all peers. Returns how many peers answered.
    pub async fn round(&mut self) -> usize {
        let started = now_secs();
        let mut ok = 0;
        for peer in self.peers.clone() {
            match self.sync_peer(&peer).await {
                Ok(n) => {
                    ok += 1;
                    if n > 0 {
                        tracing::info!("synced {n} new operations from {peer}");
                    }
                }
                Err(e) => tracing::debug!("sync with {peer} failed: {e:#}"),
            }
        }
        if ok > 0 {
            self.store.mark_synced(started);
        }
        ok
    }

    pub async fn run(mut self, interval: Duration) {
        loop {
            self.round().await;
            tokio::time::sleep(interval).await;
        }
    }
}
