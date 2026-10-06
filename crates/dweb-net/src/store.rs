//! A ledger kept on disk as an append-only log of operations.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use anyhow::{Context, Result};
use dweb_protocol::ledger::check_timestamp;
use dweb_protocol::{Hash, Ledger, NetworkConfig, Op};

/// Where an operation came from, which decides how old it may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Submitted directly by a wallet: must be within the clock skew of now.
    Local,
    /// Relayed by another node during sync: must not predate the last time
    /// this node was in sync with the network, minus the clock skew.
    Peer,
}

pub struct Store {
    ledger: RwLock<Ledger>,
    log: Mutex<Option<File>>,
    dir: Option<PathBuf>,
    /// Unix time up to which this store has seen everything its peers had.
    synced_until: AtomicU64,
}

impl Store {
    /// Opens (or creates) a store in `dir`, or an in-memory one if `None`.
    pub fn open(cfg: NetworkConfig, dir: Option<&Path>) -> Result<Self> {
        let mut ledger = Ledger::new(cfg);
        let mut log = None;
        let mut synced_until = 0;
        if let Some(dir) = dir {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("cannot create {}", dir.display()))?;
            let id_path = dir.join("network_id");
            let id = ledger.network_id().to_hex();
            match std::fs::read_to_string(&id_path) {
                Ok(existing) if existing.trim() != id => anyhow::bail!(
                    "{} holds data for a different network ({}); use another data dir",
                    dir.display(),
                    existing.trim()
                ),
                Ok(_) => {}
                Err(_) => std::fs::write(&id_path, format!("{id}\n"))?,
            }
            let path = dir.join("ops.jsonl");
            if path.exists() {
                let f = File::open(&path)?;
                for (i, line) in BufReader::new(f).lines().enumerate() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<Op>(&line) {
                        Ok(op) => {
                            if let Err(e) = ledger.insert(op) {
                                tracing::warn!("skipping invalid op on line {}: {e}", i + 1);
                            }
                        }
                        Err(e) => tracing::warn!("skipping unreadable line {}: {e}", i + 1),
                    }
                }
                ledger.refresh();
            }
            log = Some(OpenOptions::new().create(true).append(true).open(&path)?);
            synced_until = std::fs::read_to_string(dir.join("synced_until"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
        }
        Ok(Self {
            ledger: RwLock::new(ledger),
            log: Mutex::new(log),
            dir: dir.map(Path::to_path_buf),
            synced_until: AtomicU64::new(synced_until),
        })
    }

    pub fn network_id(&self) -> Hash {
        self.read(|l| l.network_id())
    }

    /// Runs `f` with read access to the ledger.
    pub fn read<R>(&self, f: impl FnOnce(&Ledger) -> R) -> R {
        f(&self.ledger.read().expect("ledger lock"))
    }

    fn not_before(&self, origin: Origin, now: u64, skew: u64) -> u64 {
        match origin {
            Origin::Local => now.saturating_sub(skew),
            Origin::Peer => match self.synced_until.load(Ordering::SeqCst) {
                0 => 0,
                t => t.saturating_sub(skew),
            },
        }
    }

    /// Validates and stores operations. Returns, per operation, its ID and
    /// whether it was new, or why it was refused.
    pub fn add_many(&self, ops: Vec<Op>, origin: Origin, now: u64) -> Vec<Result<(Hash, bool)>> {
        let mut ledger = self.ledger.write().expect("ledger lock");
        let skew = ledger.config().registration.max_clock_skew_secs;
        let not_before = self.not_before(origin, now, skew);
        let mut results = Vec::with_capacity(ops.len());
        let mut lines = String::new();
        for op in ops {
            let id = op.id();
            if ledger.contains(&id) {
                results.push(Ok((id, false)));
                continue;
            }
            let r = check_timestamp(ledger.config(), &op, now, not_before)
                .and_then(|_| {
                    let line = serde_json::to_string(&op).expect("ops serialize");
                    ledger.insert(op).map(|new| (new, line))
                })
                .map(|(new, line)| {
                    lines.push_str(&line);
                    lines.push('\n');
                    (id, new)
                })
                .map_err(anyhow::Error::from);
            results.push(r);
        }
        ledger.refresh();
        drop(ledger);
        if !lines.is_empty()
            && let Some(f) = self.log.lock().expect("log lock").as_mut()
            && let Err(e) = f.write_all(lines.as_bytes()).and_then(|_| f.flush())
        {
            tracing::error!("cannot write ledger log: {e}");
        }
        results
    }

    pub fn add(&self, op: Op, origin: Origin, now: u64) -> Result<(Hash, bool)> {
        self.add_many(vec![op], origin, now)
            .pop()
            .expect("one result")
    }

    pub fn synced_until(&self) -> u64 {
        self.synced_until.load(Ordering::SeqCst)
    }

    /// Records that everything peers had up to `t` has been fetched.
    pub fn mark_synced(&self, t: u64) {
        let prev = self.synced_until.fetch_max(t, Ordering::SeqCst);
        if t > prev
            && let Some(dir) = &self.dir
        {
            let _ = std::fs::write(dir.join("synced_until"), format!("{t}\n"));
        }
    }
}
