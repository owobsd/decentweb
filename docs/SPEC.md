# dweb protocol, version 1 (`dweb1`)

This document is enough to write a compatible wallet, registry node or
resolver in any language. The Rust code in `crates/dweb-protocol` is the
reference implementation; where they disagree, file a bug.

All integers are unsigned. "Hex" means lower-case hexadecimal without a
prefix.

## 1. Primitives

- **Signatures:** Ed25519 (RFC 8032), verified strictly (no malleable or
  small-order keys). Public keys are 32 bytes, signatures 64 bytes.
- **Hash:** SHA-256.
- **Tagged hash:** `H(tag, data) = SHA-256("dweb1" || "/" || tag || 0x00 || data)`.
  Tags used: `network-id`, `commitment`, `pow`, `op-id`.
- **Proof-of-work:** a hash meets difficulty `b` if its first `b` bits are
  zero (most significant bit of the first byte first).

## 2. Canonical encoding

Hashes and signatures are computed over this binary form, never over JSON.

| Type | Encoding |
|---|---|
| `u8` | 1 byte |
| `u64` | 8 bytes, big-endian |
| fixed (key, hash) | raw bytes, no length |
| `str` / bytes | `u16` big-endian length, then the UTF-8 bytes |
| `opt<fixed>` | `0x00` if absent, else `0x01` then the value |
| `opt<str>` | `0x00` if absent, else `0x01` then `str` |

## 3. Network config and network ID

Every network-specific choice lives in `network.toml` (see the commented
example in the repository root). The **network ID** is
`H("network-id", E)` where `E` is the concatenation of:

```
str   network_name
opt   genesis_key (32 bytes)              absent if the config value is ""
u64   genesis_cap
u64   number of genesis_schedule steps
      per step, sorted by after_days:  u64 after_days, u64 cap
u64   launch_time
u64   expiry_days
u64   pow_curve.op_bits
u64   pow_curve.commit_bits
u64   pow_curve.base_bits
u64   pow_curve.short_name_length
u64   pow_curve.extra_bits_per_char
u64   number of pow_curve.length_bits entries
      per entry, sorted by length:  u64 length, u64 bits
u64   name_rules.min_length
u64   name_rules.max_length
str   name_rules.allowed_chars
u64   registration.reveal_min_delay_secs
u64   registration.reveal_window_secs
u64   registration.max_clock_skew_secs
```

`bootstrap_nodes` and `transport` are local choices and are not part of the ID.

The network ID is inside every operation, so operations, signatures and
proof-of-work from one network are never valid on another.

A config is invalid unless `reveal_min_delay_secs > max_clock_skew_secs` and
`reveal_window_secs > reveal_min_delay_secs` (see section 8).

## 4. Names

A name is one flat string. Dots have no meaning to the protocol and nobody
owns an ending. A name is valid if, after ASCII lower-casing:

- its length is within `[min_length, max_length]` and every character is in
  `allowed_chars` (which may contain only `a-z`, `0-9`, `-`, `.`);
- splitting on `.` gives no empty part, no part over 63 characters, and no
  part starting or ending with `-`;
- it is not made only of digits and dots (so it never looks like an IP address).

Operations must carry names already in this normal form.

**Proof-of-work for a name** of `n` characters: `length_bits[n]` if set,
else `base_bits + max(0, short_name_length − n) × extra_bits_per_char`,
and never less than `op_bits`.

## 5. Operations

```
Op {
  network:   32 bytes   network ID
  timestamp: u64        unix seconds when created
  body:      Body
  signer:    opt<32>    public key; absent only for commit
  nonce:     u64        proof-of-work nonce
  signature: opt<64>    absent only for commit
}

Target { site_key: opt<32>, address: opt<str> }
```

`address` is `ip:port`, `[ipv6]:port`, `host.onion:port` or `host.i2p:port`
(at most 255 bytes). `site_key` is the Ed25519 key the site server proves it
holds (section 10). Keeping it separate from the owner key lets the owner key
stay offline.

| Tag | Body | Encoding after the tag byte | Signed by |
|---|---|---|---|
| 1 | `commit { commitment }` | `fixed commitment` | nobody |
| 2 | `reveal { commit, name, owner, salt, target }` | `fixed commit` `str name` `fixed owner` `fixed salt` target | `owner` |
| 3 | `mint { name, owner, target }` | `str name` `fixed owner` target | genesis key |
| 4 | `update { name, seq, target }` | `str name` `u64 seq` target | current owner |
| 5 | `renew { name, seq }` | `str name` `u64 seq` | current owner |
| 6 | `transfer { name, seq, new_owner }` | `str name` `u64 seq` `fixed new_owner` | current owner |

`target` encodes as `opt<fixed> site_key` then `opt<str> address`.

**Signed bytes** `S = network || u64 timestamp || u8 tag || body fields || opt signer || u64 nonce`.

- Proof-of-work: `H("pow", S)` must meet the difficulty: `commit_bits`
  (at least `op_bits`) for commits, the name's difficulty for reveals,
  `op_bits` for everything else. The genesis key's mints need only `op_bits`.
- Signature: Ed25519 over `"dweb1/sign" || 0x00 || S`.
- Operation ID: `H("op-id", S || signature)` (no signature bytes for commits).
- `S` must be at most 4096 bytes.

**Commitment** for a reveal: `H("commitment", network || str name || owner || salt)`,
with a random 32-byte `salt`.

### JSON form

On the wire operations are JSON; hex for keys, hashes and signatures:

```json
{
  "network": "5e5a…",
  "timestamp": 1791300000,
  "body": {"type": "update", "name": "alice.xyz", "seq": 1,
           "target": {"site_key": "b696…", "address": "203.0.113.5:443"}},
  "signer": "8c1f…",
  "nonce": 1234,
  "signature": "0a9e…"
}
```

`type` is one of `commit`, `reveal`, `mint`, `update`, `renew`, `transfer`.

### Stateless checks

A node refuses (does not store or relay) an operation unless: the network ID
matches; any name is valid and in normal form; keys are valid Ed25519 points;
addresses are valid; proof-of-work is sufficient; commits are unsigned and
everything else is signed with a valid signature; a reveal's signer is its
`owner`; a mint's signer is the configured genesis key.

## 6. Ledger rules

The ledger is a **set** of operations. State is a pure function of that set:
operations are replayed in order of `(timestamp, seq, id)`, where `seq` is
the body's `seq` for update/renew/transfer and 0 otherwise. Operations that
fail a rule below at their point in the replay have no effect but stay in
the set (they can take effect later if missing operations arrive).

Each name has at most one current record:
`{name, owner, target, registered_at, expires_at, seq, admin_minted, priority, free_since}`.
A record is **active** at time `t` if `t < expires_at`. `E = expiry_days × 86400`.

**Commit:** always succeeds.

**Reveal** at time `t`, referring to commit `C` (time `tc`):
1. `C` exists and its commitment equals the commitment computed from the reveal.
2. `tc + reveal_min_delay_secs ≤ t ≤ tc + reveal_window_secs`.
3. `C` has not been used by an earlier successful reveal.
4. Claim the name with priority `(tc, id(C))`.

**Mint** at time `t`: the number of successful mints so far is below the cap
at `t` (the `cap` of the last `genesis_schedule` step with
`after_days ≤ (t − launch_time) / 86400`, else `genesis_cap`); then claim
the name with priority `(t, id(mint))`. Mints are recorded with
`admin_minted = true` and count towards the cap even if later displaced.

**Claim** with priority `p` at time `t`:
- No record, or the record is not active at `t`: `free_since` is 0 or the old
  record's `expires_at`. Requires `p.time ≥ free_since` (a commit made while
  the name was still held cannot claim it).
- An active record exists: the claim wins only if `p < record.priority`,
  `p.time ≥ record.free_since`, and `t ≤ record.registered_at + reveal_window_secs`.
  This is "the earliest valid commit wins": someone who sees a reveal cannot
  take the name with a later commit.
- On success the new record is `{owner, target, registered_at = t,
  expires_at = t + E, seq = 0}`.

**Update / renew / transfer** at time `t`: the record is active at `t`, the
signer is the record's owner, and `seq = record.seq + 1`. Then `record.seq = seq` and:
- update: `target` is replaced;
- renew: `expires_at = max(expires_at, t + E)`;
- transfer: `owner = new_owner`.

Nothing else can change a record. No key, including the genesis key, can
edit, revoke or transfer a name it does not own. Expiry is the only way a
name disappears.

## 7. Registration flow

1. Pick a random `salt`; publish `commit { commitment }`.
2. Wait at least `reveal_min_delay_secs`.
3. Publish `reveal`, with the name's proof-of-work, before
   `reveal_window_secs` have passed.

## 8. Time

There is no blockchain; ordering comes from operation timestamps, checked
against node clocks when an operation is first seen:

- An operation more than `max_clock_skew_secs` in the future is refused.
- A wallet's direct submission older than `now − max_clock_skew_secs` is refused.
- An operation relayed by a peer is refused if it is older than
  `synced_until − max_clock_skew_secs`, where `synced_until` is the last time
  this node completed a sync round. A new node (never synced) accepts
  history of any age.

So nobody can back-date an operation by more than `max_clock_skew_secs`.
Because `reveal_min_delay_secs > max_clock_skew_secs`, a watcher who sees a
reveal cannot back-date a commit to before the real owner's commit.

Accepted weaknesses:
- A newly joining node trusts the history its peers give it. A malicious
  peer could feed it back-dated operations. Bootstrap from several nodes you
  have reason to trust.
- If an operation reaches only a node that then stays offline for longer
  than the clock skew, other nodes will refuse it when it reappears.
- A status reported right after submission can change while other operations
  with nearby timestamps propagate (for example, two claims in the same
  second are ordered by ID).

## 9. Registry API

HTTP/1.1, JSON bodies. Nodes should also be reachable as Tor/I2P services.

| Request | Response |
|---|---|
| `GET /v1/info` | `{network_name, network_id, node_id, ops, active_names, admin_minted}` |
| `POST /v1/ops` (body: Op) | `{id, new, status}`; 400 `{error}` if refused |
| `GET /v1/ops?from=N&limit=M` | `{ops: [Op…], next}`: ops in this node's arrival order, from index N (M ≤ 1000) |
| `GET /v1/ops/{id}` | `{op, status}` or 404 |
| `GET /v1/names/{name}` | `{record, active}` or 404 |

`status` is `{"status": "applied"}` or `{"status": "rejected", "reason": "…"}`.
`record` is `{name, owner, target, registered_at, expires_at, seq, admin_minted, registered_by}`.

**Replication:** each node polls each peer's `/v1/ops` with a per-peer cursor
and adds what it does not have (subject to section 8). A node that accepts a
new operation from a wallet also pushes it to its peers with `POST /v1/ops`.
`node_id` lets a node skip itself if it appears in its own peer list.

## 10. Sites and resolvers

**Site server:** serves HTTPS (TLS 1.3 only, ALPN `http/1.1`) with a
self-signed X.509 certificate whose key is the Ed25519 site key. Names,
dates and issuer in the certificate are ignored.

**Resolver:** for a visited name it
1. finds the active record in its own copy of the ledger (synced as in
   section 9, so no single node is trusted);
2. connects to `target.address`, through a SOCKS5 proxy (Tor or I2P) if
   configured, sending the host name to the proxy (no local DNS);
3. completes a TLS 1.3 handshake, accepting the server only if the
   certificate's Ed25519 key equals `target.site_key` and the handshake
   signature verifies with it;
4. never falls back to plain HTTP or to DNS.

The reference resolver is an HTTP proxy on 127.0.0.1. For `CONNECT` it
terminates the browser's TLS with a certificate from a local certificate
authority that is generated on the user's machine, never exported, and
trusted only by the dedicated browser profile. Blocklists are applied here,
locally, by the user's choice.
