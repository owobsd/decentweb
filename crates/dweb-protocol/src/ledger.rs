//! The ledger: a set of operations and the deterministic rules that turn it
//! into name records.
//!
//! Nodes exchange operations, never state. Any node holding the same set of
//! operations computes exactly the same records, whatever order it received
//! them in, because operations are always replayed in `(timestamp, seq, id)`
//! order (see [`replay_key`]). An operation that is invalid at its point in the replay (a reveal
//! for a taken name, an update signed by the wrong key) is kept but has no
//! effect.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::config::NetworkConfig;
use crate::crypto::{Hash, PublicKey};
use crate::error::{Error, Result};
use crate::op::{Op, OpBody, Target, commitment};

/// The current state of one name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameRecord {
    pub name: String,
    pub owner: PublicKey,
    pub target: Target,
    pub registered_at: u64,
    pub expires_at: u64,
    /// Number of owner operations applied since registration. The next
    /// update, renew or transfer must carry `seq + 1`.
    pub seq: u64,
    /// True if the genesis key minted this name for free.
    pub admin_minted: bool,
    /// Operation that created this registration.
    pub registered_by: Hash,
    /// Claim priority: the commit time for reveals, the op time for mints.
    #[serde(skip)]
    priority: (u64, Hash),
    /// Earliest commit time allowed to claim this registration's slot.
    #[serde(skip)]
    free_since: u64,
}

impl NameRecord {
    pub fn is_active(&self, now: u64) -> bool {
        now < self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OpStatus {
    /// The operation took effect (for a commit: it is recorded).
    Applied,
    /// The operation is stored but had no effect, for the given reason. It
    /// can still become applied if missing operations arrive later.
    Rejected { reason: String },
}

#[derive(Default)]
struct State {
    names: HashMap<String, NameRecord>,
    status: HashMap<Hash, OpStatus>,
    admin_minted: u64,
}

pub struct Ledger {
    cfg: NetworkConfig,
    network_id: Hash,
    ops: HashMap<Hash, Op>,
    /// Insertion order, used for incremental sync between nodes.
    order: Vec<Hash>,
    state: State,
    dirty: bool,
}

impl Ledger {
    pub fn new(cfg: NetworkConfig) -> Self {
        let network_id = cfg.network_id();
        Self {
            cfg,
            network_id,
            ops: HashMap::new(),
            order: Vec::new(),
            state: State::default(),
            dirty: false,
        }
    }

    pub fn config(&self) -> &NetworkConfig {
        &self.cfg
    }

    pub fn network_id(&self) -> Hash {
        self.network_id
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub fn contains(&self, id: &Hash) -> bool {
        self.ops.contains_key(id)
    }

    pub fn get(&self, id: &Hash) -> Option<&Op> {
        self.ops.get(id)
    }

    /// Validates and stores an operation. Returns `false` if it was already
    /// known. Call [`Ledger::refresh`] afterwards to update the records.
    pub fn insert(&mut self, op: Op) -> Result<bool> {
        op.check_stateless(&self.cfg, &self.network_id)?;
        let id = op.id();
        if self.ops.contains_key(&id) {
            return Ok(false);
        }
        self.ops.insert(id, op);
        self.order.push(id);
        self.dirty = true;
        Ok(true)
    }

    /// Operations in the order this ledger received them, from `start`.
    pub fn ops_from(&self, start: usize, limit: usize) -> Vec<&Op> {
        self.order
            .iter()
            .skip(start)
            .take(limit)
            .filter_map(|id| self.ops.get(id))
            .collect()
    }

    /// The latest registration of `name`, active or expired.
    pub fn record(&self, name: &str) -> Option<&NameRecord> {
        debug_assert!(!self.dirty, "call refresh() after insert()");
        self.state.names.get(name)
    }

    /// The registration of `name` if it is active at `now`.
    pub fn lookup(&self, name: &str, now: u64) -> Option<&NameRecord> {
        self.record(name).filter(|r| r.is_active(now))
    }

    pub fn status(&self, id: &Hash) -> Option<&OpStatus> {
        self.state.status.get(id)
    }

    /// How many free names the genesis key has minted.
    pub fn admin_minted_count(&self) -> u64 {
        self.state.admin_minted
    }

    pub fn active_names(&self, now: u64) -> impl Iterator<Item = &NameRecord> {
        self.state.names.values().filter(move |r| r.is_active(now))
    }

    /// Recomputes every record from the full set of operations.
    pub fn refresh(&mut self) {
        if !self.dirty {
            return;
        }
        self.state = self.replay();
        self.dirty = false;
    }

    fn replay(&self) -> State {
        let mut sorted: Vec<(&Hash, &Op)> = self.ops.iter().collect();
        sorted.sort_by_key(|(id, op)| replay_key(id, op));

        let commits: HashMap<Hash, (u64, Hash)> = self
            .ops
            .iter()
            .filter_map(|(id, op)| match op.body {
                OpBody::Commit { commitment } => Some((*id, (op.timestamp, commitment))),
                _ => None,
            })
            .collect();

        let mut st = State::default();
        let mut used_commits = HashSet::new();
        for (id, op) in sorted {
            let result = self.apply(&mut st, &commits, &mut used_commits, id, op);
            let status = match result {
                Ok(()) => OpStatus::Applied,
                Err(reason) => OpStatus::Rejected { reason },
            };
            st.status.insert(*id, status);
        }
        st
    }

    fn apply(
        &self,
        st: &mut State,
        commits: &HashMap<Hash, (u64, Hash)>,
        used_commits: &mut HashSet<Hash>,
        id: &Hash,
        op: &Op,
    ) -> std::result::Result<(), String> {
        let rules = &self.cfg.registration;
        let ts = op.timestamp;
        match &op.body {
            OpBody::Commit { .. } => Ok(()),

            OpBody::Reveal {
                commit,
                name,
                owner,
                salt,
                target,
            } => {
                let (commit_ts, value) = *commits
                    .get(commit)
                    .ok_or("the commit this reveal refers to is unknown")?;
                if value != commitment(&self.network_id, name, owner, salt) {
                    return Err("reveal does not match its commit".into());
                }
                if ts < commit_ts.saturating_add(rules.reveal_min_delay_secs) {
                    return Err("reveal came too soon after its commit".into());
                }
                if ts > commit_ts.saturating_add(rules.reveal_window_secs) {
                    return Err("reveal came too late after its commit".into());
                }
                if used_commits.contains(commit) {
                    return Err("commit already used".into());
                }
                self.claim(
                    st,
                    name,
                    *owner,
                    target,
                    ts,
                    (commit_ts, *commit),
                    *id,
                    false,
                )?;
                used_commits.insert(*commit);
                Ok(())
            }

            OpBody::Mint {
                name,
                owner,
                target,
            } => {
                if st.admin_minted >= self.cfg.genesis_cap_at(ts) {
                    return Err("genesis free-name allowance is used up".into());
                }
                self.claim(st, name, *owner, target, ts, (ts, *id), *id, true)?;
                st.admin_minted += 1;
                Ok(())
            }

            OpBody::Update { name, seq, target } => {
                let rec = Self::owned(st, name, op, *seq)?;
                rec.target = target.clone();
                rec.seq = *seq;
                Ok(())
            }

            OpBody::Renew { name, seq } => {
                let expiry = self.cfg.expiry_secs();
                let rec = Self::owned(st, name, op, *seq)?;
                rec.expires_at = rec.expires_at.max(ts.saturating_add(expiry));
                rec.seq = *seq;
                Ok(())
            }

            OpBody::Transfer {
                name,
                seq,
                new_owner,
            } => {
                let rec = Self::owned(st, name, op, *seq)?;
                rec.owner = *new_owner;
                rec.seq = *seq;
                Ok(())
            }
        }
    }

    /// Claims a name for a reveal or mint.
    ///
    /// A free name goes to the first claim. A taken name can still be won,
    /// within `reveal_window_secs` of its registration, by a claim with an
    /// earlier commit: this is the "earliest valid commit wins" rule, and it
    /// stops anyone who sees a reveal from racing in with their own.
    #[allow(clippy::too_many_arguments)]
    fn claim(
        &self,
        st: &mut State,
        name: &str,
        owner: PublicKey,
        target: &Target,
        ts: u64,
        priority: (u64, Hash),
        op_id: Hash,
        admin_minted: bool,
    ) -> std::result::Result<(), String> {
        let window = self.cfg.registration.reveal_window_secs;
        let free_since = match st.names.get(name) {
            None => 0,
            Some(cur) if !cur.is_active(ts) => cur.expires_at,
            Some(cur) => {
                let contestable = ts <= cur.registered_at.saturating_add(window);
                if contestable && priority < cur.priority && priority.0 >= cur.free_since {
                    cur.free_since
                } else {
                    return Err("name is already registered".into());
                }
            }
        };
        if priority.0 < free_since {
            return Err("commit was made before the name became free".into());
        }
        st.names.insert(
            name.to_string(),
            NameRecord {
                name: name.to_string(),
                owner,
                target: target.clone(),
                registered_at: ts,
                expires_at: ts.saturating_add(self.cfg.expiry_secs()),
                seq: 0,
                admin_minted,
                registered_by: op_id,
                priority,
                free_since,
            },
        );
        Ok(())
    }

    /// The active record for `name`, if `op` is signed by its owner with the
    /// next sequence number.
    fn owned<'a>(
        st: &'a mut State,
        name: &str,
        op: &Op,
        seq: u64,
    ) -> std::result::Result<&'a mut NameRecord, String> {
        let rec = st
            .names
            .get_mut(name)
            .filter(|r| r.is_active(op.timestamp))
            .ok_or("name is not registered or has expired")?;
        if op.signer != Some(rec.owner) {
            return Err("not signed by the name's owner".into());
        }
        if seq != rec.seq + 1 {
            return Err(format!("wrong sequence number (expected {})", rec.seq + 1));
        }
        Ok(rec)
    }
}

/// Replay order: by timestamp, then by sequence number (so an owner's
/// operations made within the same second apply in the order they were
/// made), then by ID.
pub fn replay_key(id: &Hash, op: &Op) -> (u64, u64, Hash) {
    let seq = match &op.body {
        OpBody::Update { seq, .. } | OpBody::Renew { seq, .. } | OpBody::Transfer { seq, .. } => {
            *seq
        }
        _ => 0,
    };
    (op.timestamp, seq, *id)
}

/// Checks an operation's timestamp when a node first sees it.
///
/// It must not be in the future, must be within the clock skew of `now`
/// when submitted directly, and must not be older than `not_before` when
/// relayed by a peer. This is what stops back-dated commits; see
/// `docs/SPEC.md` "Time".
pub fn check_timestamp(cfg: &NetworkConfig, op: &Op, now: u64, not_before: u64) -> Result<()> {
    let skew = cfg.registration.max_clock_skew_secs;
    if op.timestamp > now.saturating_add(skew) {
        return Err(Error::Op("timestamp is in the future".into()));
    }
    if op.timestamp < not_before {
        return Err(Error::Op("timestamp is too old".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_config;
    use crate::crypto::SecretKey;

    struct Net {
        cfg: NetworkConfig,
        ledger: Ledger,
    }

    impl Net {
        fn new() -> Self {
            Self::with(test_config())
        }

        fn with(cfg: NetworkConfig) -> Self {
            Self {
                ledger: Ledger::new(cfg.clone()),
                cfg,
            }
        }

        fn add(&mut self, op: Op) -> Hash {
            let id = op.id();
            self.ledger.insert(op).unwrap();
            self.ledger.refresh();
            id
        }

        fn status(&self, id: &Hash) -> OpStatus {
            self.ledger.status(id).cloned().unwrap()
        }

        fn op(&self, ts: u64, body: OpBody, key: Option<&SecretKey>) -> Op {
            Op::create(&self.cfg, ts, body, key).unwrap()
        }

        /// Returns (commit op, reveal op) for `name`.
        fn registration(
            &self,
            name: &str,
            key: &SecretKey,
            commit_ts: u64,
            reveal_ts: u64,
        ) -> (Op, Op) {
            let salt = Hash([commit_ts as u8; 32]);
            let c = commitment(&self.cfg.network_id(), name, &key.public(), &salt);
            let commit = self.op(commit_ts, OpBody::Commit { commitment: c }, None);
            let reveal = self.op(
                reveal_ts,
                OpBody::Reveal {
                    commit: commit.id(),
                    name: name.into(),
                    owner: key.public(),
                    salt,
                    target: Target::default(),
                },
                Some(key),
            );
            (commit, reveal)
        }

        fn register(
            &mut self,
            name: &str,
            key: &SecretKey,
            commit_ts: u64,
            reveal_ts: u64,
        ) -> Hash {
            let (c, r) = self.registration(name, key, commit_ts, reveal_ts);
            self.add(c);
            self.add(r)
        }
    }

    fn key() -> SecretKey {
        SecretKey::generate().unwrap()
    }

    #[test]
    fn register_update_renew_transfer() {
        let mut n = Net::new();
        let alice = key();
        let bob = key();
        let r = n.register("alice.xyz", &alice, 100, 120);
        assert_eq!(n.status(&r), OpStatus::Applied);
        let rec = n.ledger.lookup("alice.xyz", 130).unwrap().clone();
        assert_eq!(rec.owner, alice.public());
        assert_eq!(rec.expires_at, 120 + 86_400);

        let target = Target {
            site_key: Some(alice.public()),
            address: Some("1.2.3.4:443".into()),
        };
        let u = n.add(n.op(
            200,
            OpBody::Update {
                name: "alice.xyz".into(),
                seq: 1,
                target: target.clone(),
            },
            Some(&alice),
        ));
        assert_eq!(n.status(&u), OpStatus::Applied);
        assert_eq!(n.ledger.lookup("alice.xyz", 300).unwrap().target, target);

        // Bob cannot touch Alice's name.
        let evil = n.add(n.op(
            300,
            OpBody::Transfer {
                name: "alice.xyz".into(),
                seq: 2,
                new_owner: bob.public(),
            },
            Some(&bob),
        ));
        assert!(matches!(n.status(&evil), OpStatus::Rejected { .. }));

        let renew = n.add(n.op(
            1000,
            OpBody::Renew {
                name: "alice.xyz".into(),
                seq: 2,
            },
            Some(&alice),
        ));
        assert_eq!(n.status(&renew), OpStatus::Applied);
        assert_eq!(
            n.ledger.lookup("alice.xyz", 1).unwrap().expires_at,
            1000 + 86_400
        );

        // A replayed sequence number is rejected.
        let replay = n.add(n.op(
            1001,
            OpBody::Renew {
                name: "alice.xyz".into(),
                seq: 2,
            },
            Some(&alice),
        ));
        assert!(matches!(n.status(&replay), OpStatus::Rejected { .. }));

        let t = n.add(n.op(
            2000,
            OpBody::Transfer {
                name: "alice.xyz".into(),
                seq: 3,
                new_owner: bob.public(),
            },
            Some(&alice),
        ));
        assert_eq!(n.status(&t), OpStatus::Applied);
        assert_eq!(
            n.ledger.lookup("alice.xyz", 2001).unwrap().owner,
            bob.public()
        );
    }

    #[test]
    fn reveal_timing() {
        let mut n = Net::new();
        let a = key();
        let early = n.register("early.xyz", &a, 100, 105);
        assert!(matches!(n.status(&early), OpStatus::Rejected { .. }));
        let late = n.register("late.xyz", &a, 100, 300);
        assert!(matches!(n.status(&late), OpStatus::Rejected { .. }));
    }

    #[test]
    fn reveal_must_match_commit() {
        let mut n = Net::new();
        let a = key();
        let thief = key();
        let (commit, reveal) = n.registration("alice.xyz", &a, 100, 120);
        n.add(commit);
        // Someone who sees the reveal cannot reuse the commit for themselves.
        let OpBody::Reveal {
            commit,
            name,
            salt,
            target,
            ..
        } = reveal.body.clone()
        else {
            unreachable!()
        };
        let stolen = n.add(n.op(
            115,
            OpBody::Reveal {
                commit,
                name,
                owner: thief.public(),
                salt,
                target,
            },
            Some(&thief),
        ));
        assert!(matches!(n.status(&stolen), OpStatus::Rejected { .. }));
        let ok = n.add(reveal);
        assert_eq!(n.status(&ok), OpStatus::Applied);
    }

    #[test]
    fn earliest_commit_wins_even_if_revealed_later() {
        let mut n = Net::new();
        let first = key();
        let second = key();
        // second commits later but reveals first.
        let r2 = n.register("x.xyz", &second, 110, 125);
        assert_eq!(
            n.ledger.lookup("x.xyz", 126).unwrap().owner,
            second.public()
        );
        let r1 = n.register("x.xyz", &first, 100, 130);
        assert_eq!(n.status(&r1), OpStatus::Applied);
        assert!(matches!(n.status(&r2), OpStatus::Applied));
        assert_eq!(n.ledger.lookup("x.xyz", 131).unwrap().owner, first.public());

        // A later commit cannot take a held name.
        let third = key();
        let r3 = n.register("x.xyz", &third, 140, 185);
        assert!(matches!(n.status(&r3), OpStatus::Rejected { .. }));
    }

    #[test]
    fn order_of_arrival_does_not_matter() {
        let a = key();
        let b = key();
        let base = Net::new();
        let mut ops = vec![];
        let (c1, r1) = base.registration("same.xyz", &a, 100, 130);
        let (c2, r2) = base.registration("same.xyz", &b, 110, 125);
        ops.extend([c1, r1, c2, r2]);
        let mut results = vec![];
        for perm in [[0, 1, 2, 3], [3, 2, 1, 0], [2, 3, 0, 1], [1, 3, 0, 2]] {
            let mut n = Net::new();
            for i in perm {
                n.ledger.insert(ops[i].clone()).unwrap();
            }
            n.ledger.refresh();
            results.push(n.ledger.lookup("same.xyz", 200).unwrap().owner);
        }
        assert!(results.iter().all(|o| *o == a.public()));
    }

    #[test]
    fn expiry_returns_name_to_pool() {
        let mut n = Net::new();
        let a = key();
        let b = key();
        n.register("e.xyz", &a, 100, 120);
        let expires = 120 + 86_400;
        assert!(n.ledger.lookup("e.xyz", expires).is_none());
        // A renew after expiry does nothing.
        let late = n.add(n.op(
            expires + 1,
            OpBody::Renew {
                name: "e.xyz".into(),
                seq: 1,
            },
            Some(&a),
        ));
        assert!(matches!(n.status(&late), OpStatus::Rejected { .. }));
        // A commit made before expiry cannot claim the freed name.
        let pre = n.register("e.xyz", &b, expires - 20, expires + 5);
        assert!(matches!(n.status(&pre), OpStatus::Rejected { .. }));
        let r = n.register("e.xyz", &b, expires + 1, expires + 20);
        assert_eq!(n.status(&r), OpStatus::Applied);
        assert_eq!(
            n.ledger.lookup("e.xyz", expires + 21).unwrap().owner,
            b.public()
        );
    }

    #[test]
    fn genesis_mints_are_capped_and_powerless() {
        let genesis = key();
        let mut cfg = test_config();
        cfg.genesis_key = genesis.public().to_hex();
        let mut n = Net::with(cfg);
        let alice = key();

        n.register("alice.xyz", &alice, 100, 120);
        // Genesis cannot mint over an existing name...
        let over = n.add(n.op(
            200,
            OpBody::Mint {
                name: "alice.xyz".into(),
                owner: genesis.public(),
                target: Target::default(),
            },
            Some(&genesis),
        ));
        assert!(matches!(n.status(&over), OpStatus::Rejected { .. }));
        // ...or edit it.
        let edit = n.add(n.op(
            201,
            OpBody::Transfer {
                name: "alice.xyz".into(),
                seq: 1,
                new_owner: genesis.public(),
            },
            Some(&genesis),
        ));
        assert!(matches!(n.status(&edit), OpStatus::Rejected { .. }));

        for (i, name) in ["a.free", "b.free", "c.free"].iter().enumerate() {
            let id = n.add(n.op(
                300 + i as u64,
                OpBody::Mint {
                    name: name.to_string(),
                    owner: alice.public(),
                    target: Target::default(),
                },
                Some(&genesis),
            ));
            let expect_ok = i < 2;
            assert_eq!(n.status(&id) == OpStatus::Applied, expect_ok, "{name}");
        }
        assert_eq!(n.ledger.admin_minted_count(), 2);
        assert!(n.ledger.lookup("a.free", 400).unwrap().admin_minted);

        // A non-genesis key cannot mint at all.
        let fake = Op::create(
            &n.cfg,
            500,
            OpBody::Mint {
                name: "d.free".into(),
                owner: alice.public(),
                target: Target::default(),
            },
            Some(&alice),
        )
        .unwrap();
        assert!(n.ledger.insert(fake).is_err());
    }

    #[test]
    fn earlier_commit_beats_genesis_mint() {
        let genesis = key();
        let mut cfg = test_config();
        cfg.genesis_key = genesis.public().to_hex();
        let mut n = Net::with(cfg);
        let alice = key();
        let (commit, reveal) = n.registration("want.xyz", &alice, 100, 120);
        n.add(commit);
        // Genesis sees the commit time window and mints first.
        n.add(n.op(
            115,
            OpBody::Mint {
                name: "want.xyz".into(),
                owner: genesis.public(),
                target: Target::default(),
            },
            Some(&genesis),
        ));
        n.add(reveal);
        assert_eq!(
            n.ledger.lookup("want.xyz", 121).unwrap().owner,
            alice.public()
        );
    }

    #[test]
    fn same_second_owner_ops_apply_in_seq_order() {
        let mut n = Net::new();
        let a = key();
        let b = key();
        n.register("s.xyz", &a, 100, 120);
        let renew = n.op(
            200,
            OpBody::Renew {
                name: "s.xyz".into(),
                seq: 1,
            },
            Some(&a),
        );
        let transfer = n.op(
            200,
            OpBody::Transfer {
                name: "s.xyz".into(),
                seq: 2,
                new_owner: b.public(),
            },
            Some(&a),
        );
        let (r, t) = (n.add(renew), n.add(transfer));
        assert_eq!(n.status(&r), OpStatus::Applied);
        assert_eq!(n.status(&t), OpStatus::Applied);
        assert_eq!(n.ledger.lookup("s.xyz", 201).unwrap().owner, b.public());
    }

    #[test]
    fn timestamps() {
        let cfg = test_config();
        let op = Op::create(
            &cfg,
            1000,
            OpBody::Commit {
                commitment: Hash::ZERO,
            },
            None,
        )
        .unwrap();
        check_timestamp(&cfg, &op, 1000, 0).unwrap();
        check_timestamp(&cfg, &op, 996, 0).unwrap();
        assert!(check_timestamp(&cfg, &op, 990, 0).is_err());
        assert!(check_timestamp(&cfg, &op, 1000, 1001).is_err());
    }
}
