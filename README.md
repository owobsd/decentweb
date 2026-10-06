# decentweb

A separate, censorship-resistant web. Anyone can own any name, with any
ending (`alice.xyz`, `my.site`, `x`), and host a site from their own server.
No company, registrar or government can take it down.

This is a new namespace, not an add-on to DNS. It never overrides or
interacts with real domains.

- **Key equals ownership.** Whoever holds the private key owns the name.
  There is no support desk, takedown form or appeals process.
- **No admin power over others.** No key, not even the genesis key, can
  revoke, transfer or edit a name it does not own.
- **No money.** Names are claimed with proof-of-work, not payment.
- **Many copies of the ledger.** Every registry node holds the full name list.
- **Private by default.** Lookups and site connections can run over Tor or I2P.
- **Neutral expiry only.** Names expire if not renewed, the same for everyone.
- **Filtering is a client choice.** Anyone can run a resolver with their own
  blocklist. The network itself never removes anything.

## How it works

```
  wallet ──signed ops──▶ registry nodes ◀──sync──▶ registry nodes
                              │
                              ▼ (full ledger copy)
  browser ──proxy──▶ resolver (127.0.0.1) ──key-pinned TLS──▶ site server
  (LibreWolf profile)   checks the server holds the registered key
```

| Program | What it does |
|---|---|
| `dweb-wallet` | Generates keys; registers, updates, renews and transfers names |
| `dweb-node` | Registry node: validates every operation, stores and replicates the ledger |
| `dweb-site` | Serves a static site (or reverse-proxies a local service) over TLS with its site key |
| `dweb-resolver` | Local proxy: looks names up in its own ledger copy, verifies keys, connects |

A record holds the name, the owner's public key, the server address (IP or
onion), the site key the server must prove it holds, and an expiry time.

## Quick start (local test network)

```sh
cargo build --release
export PATH="$PWD/target/release:$PATH"

# 1. A registry node (uses ./network.toml)
dweb-node --data-dir ./node-data &

# 2. Your owner key. Back it up: lost keys mean lost names.
dweb-wallet keygen --out owner.key

# 3. A site server; it creates site.key and prints its public key
mkdir site && echo '<h1>hello</h1>' > site/index.html
SITE_KEY=$(dweb-site --print-key)
dweb-site --root site --listen 127.0.0.1:8443 &

# 4. Claim a name and point it at the server (commit, wait 10 min, reveal)
dweb-wallet register alice.xyz --key owner.key \
  --site-key "$SITE_KEY" --address 127.0.0.1:8443

# 5. Visit it through the resolver
dweb-resolver &
curl -x http://127.0.0.1:7780 http://alice.xyz/
```

For everyday browsing, install the resolver and the dedicated LibreWolf
profile with `browser/install.sh` (Linux, macOS) or `browser/install.ps1`
(Windows), then run `dweb-browser`. Your normal browser is not changed.

`scripts/e2e.sh` runs the whole flow on a throwaway network: two replicating
nodes, registration, HTTPS through the local certificate authority, genesis
mints, blocklists, impersonation and transfer checks.

## Wallet commands

```
dweb-wallet keygen --out owner.key
dweb-wallet lookup alice.xyz
dweb-wallet register alice.xyz --key owner.key [--site-key HEX] [--address IP:PORT]
dweb-wallet update   alice.xyz --key owner.key [--site-key HEX] [--address IP:PORT]
dweb-wallet renew    alice.xyz --key owner.key
dweb-wallet transfer alice.xyz --key owner.key --to NEW_OWNER_PUBKEY
dweb-wallet mint     free.xyz  --genesis-key genesis.key --owner PUBKEY   # genesis key only
```

`dweb-site --publish alice.xyz --owner-key owner.key --public-address IP:PORT`
points the name at the server when it starts.

## Repository layout

```
crates/dweb-protocol   shared library: records, signatures, proof-of-work,
                       commit-and-reveal, ledger rules, network.toml loader
crates/dweb-net        node, resolver and site server programs
crates/dweb-wallet     wallet and command-line tool
network.toml           every network-specific setting
browser/               LibreWolf profile and installers
docs/SPEC.md           wire format and rules, for other implementations
docs/FORK_GUIDE.md     launch your own network
docs/OPERATORS.md      abuse stance and responsibilities of node and site operators
```

## Start your own network

Edit `network.toml` (name, genesis key, bootstrap nodes) and start a node.
No source changes. See [docs/FORK_GUIDE.md](docs/FORK_GUIDE.md).

## Known limits

- Early on, few registry nodes means weak decentralisation.
- Visitors must install software (the resolver and browser profile).
- Lost keys mean permanently lost names.
- Ordering relies on timestamps checked against node clocks, not a
  blockchain; see "Time" in [docs/SPEC.md](docs/SPEC.md) for what that means.

Read [docs/OPERATORS.md](docs/OPERATORS.md) before running a node or hosting
the software.

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option.
