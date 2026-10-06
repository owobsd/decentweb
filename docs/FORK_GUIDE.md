# Launching your own network

A new, independent network is one edited file and one command. You do not
change any source code.

Your network will have its own network ID. Its names, signatures and traffic
can never be confused with any other network's, even one running the same
software.

## 1. Build or download the programs

```sh
cargo build --release
export PATH="$PWD/target/release:$PATH"
```

## 2. Make a genesis key (optional), offline

The genesis key can mint free names without proof-of-work, and nothing else.
It cannot revoke, transfer or edit any name it does not own. Every free mint
is public and tagged as admin-minted.

Generate it on a computer that is not connected to the internet, and keep the
key file offline:

```sh
dweb-wallet keygen --out genesis.key
```

Copy only the printed **public key** into the config. Because it is in the
config before launch, it exists from the first moment and nobody can race to
claim it. If the key is ever stolen, the thief can mint free names up to your
cap, but gains no power over existing names.

Do not want a genesis key at all? Leave `genesis_key = ""`.

## 3. Edit `network.toml`

Copy the example `network.toml` and change at least:

| Setting | Set it to |
|---|---|
| `network_name` | a name for your network, e.g. `"freenet-de"` |
| `genesis_key` | the public key from step 2, or `""` |
| `genesis_cap`, `genesis_schedule` | how many free names, and how that tapers over time |
| `launch_time` | the unix time you launch (`date +%s`); the taper counts from here |
| `bootstrap_nodes` | the address of your first node, e.g. `["http://203.0.113.5:7700"]` |

Tune the rest to taste:

- `pow_curve`: how much work names cost. Each bit doubles the work.
  `base_bits = 22` takes a few seconds on a laptop; 30 takes minutes to hours.
- `name_rules`: allowed characters and lengths.
- `expiry_days`: how long a name lasts between renewals.
- `registration`: timing of commit and reveal. Keep
  `reveal_min_delay_secs` greater than `max_clock_skew_secs`.

Check the result and note your network ID:

```sh
dweb-wallet --config network.toml network-id
```

Every setting except `bootstrap_nodes` and `[transport]` is part of the
network ID. Change any of them after launch and you have made yet another
network, so settle them first.

## 4. Start the first node

```sh
dweb-node --config network.toml --listen 0.0.0.0:7700 --data-dir ./node-data
```

Put the node behind your firewall rules as you see fit. To make it reachable
over Tor, add a hidden service pointing at port 7700 and list the `.onion`
address in `bootstrap_nodes` too.

More nodes join by running the same command with the same `network.toml`;
they find each other through `bootstrap_nodes` (or `--peer URL`). Ask
volunteers to run nodes early: few nodes means weak decentralisation.

## 5. Claim a name and open a site

```sh
dweb-wallet --config network.toml keygen --out owner.key
mkdir site && echo '<h1>first site</h1>' > site/index.html
dweb-site --config network.toml --root site --listen 0.0.0.0:8443 --print-key
dweb-wallet --config network.toml register hello.net --key owner.key \
  --site-key <key printed above> --address <your public ip>:8443
dweb-site --config network.toml --root site --listen 0.0.0.0:8443
```

Or mint it for free with the genesis key:

```sh
dweb-wallet --config network.toml mint hello.net --genesis-key genesis.key \
  --owner $(dweb-wallet pubkey owner.key) --site-key <site key> --address <ip>:8443
```

## 6. Ship the browser bundle

Put your `network.toml` next to the programs and the `browser/` folder (or
use `scripts/package.sh`, which does this), and tell users to run
`browser/install.sh` or `browser/install.ps1`. Then they open `dweb-browser`
and type `hello.net`.

## 7. Publish

- Your `network.toml` (it is public; it holds only public keys).
- Your network ID, so users can check they have the right config.
- The source, under MIT or Apache-2.0 like this project.
- Read [OPERATORS.md](OPERATORS.md) and get legal advice for your country
  before launch.
