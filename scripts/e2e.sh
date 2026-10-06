#!/usr/bin/env bash
# End-to-end test: launches a throwaway network on localhost with two
# replicating registry nodes, claims a name, serves a site, and loads it
# through the resolver over HTTP and HTTPS (local CA). Also checks genesis
# mints, local blocklists, and that a server with the wrong key is refused.
#
# Usage: scripts/e2e.sh   (builds in release mode first)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cargo build --release --quiet --manifest-path "$ROOT/Cargo.toml"
BIN="$ROOT/target/release"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

pass() { printf '  \033[32mok\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_http() { for _ in $(seq 50); do curl -s -o /dev/null "$1" && return 0; sleep 0.2; done; fail "$1 never came up"; }
export RUST_LOG=warn

echo "== keys and config"
"$BIN/dweb-wallet" keygen --out genesis.key 2>/dev/null >/dev/null
"$BIN/dweb-wallet" keygen --out alice.key 2>/dev/null >/dev/null
"$BIN/dweb-wallet" keygen --out bob.key 2>/dev/null >/dev/null
GENESIS=$("$BIN/dweb-wallet" pubkey genesis.key)
BOB=$("$BIN/dweb-wallet" pubkey bob.key)

# A fork is just a different network.toml.
cat > network.toml <<TOML
network_name = "e2e-test"
genesis_key = "$GENESIS"
genesis_cap = 1
expiry_days = 365
bootstrap_nodes = ["http://127.0.0.1:17701", "http://127.0.0.1:17702"]
[pow_curve]
op_bits = 4
commit_bits = 6
base_bits = 10
short_name_length = 4
extra_bits_per_char = 1
[registration]
reveal_min_delay_secs = 3
reveal_window_secs = 120
max_clock_skew_secs = 2
TOML
export DWEB_CONFIG="$WORK/network.toml"
pass "network id $("$BIN/dweb-wallet" network-id)"

echo "== registry nodes"
"$BIN/dweb-node" --listen 127.0.0.1:17701 --data-dir node1 --sync-interval 1 & PIDS+=($!)
"$BIN/dweb-node" --listen 127.0.0.1:17702 --data-dir node2 --sync-interval 1 & PIDS+=($!)
wait_http http://127.0.0.1:17701/v1/info
wait_http http://127.0.0.1:17702/v1/info
pass "two nodes up"

echo "== site server"
mkdir site && echo '<h1>hello from alice</h1>' > site/index.html
SITE_KEY=$("$BIN/dweb-site" --key site.key --print-key)
"$BIN/dweb-site" --key site.key --root site --listen 127.0.0.1:17443 & PIDS+=($!)
sleep 0.5
pass "site key $SITE_KEY"

echo "== register alice.xyz on node 1"
"$BIN/dweb-wallet" --registry http://127.0.0.1:17701 register alice.xyz --key alice.key \
  --site-key "$SITE_KEY" --address 127.0.0.1:17443 >/dev/null 2>&1 || fail "register"
pass "registered"
sleep 2
"$BIN/dweb-wallet" --registry http://127.0.0.1:17702 lookup alice.xyz | grep -q "status:      active" \
  || fail "node 2 did not replicate the name"
pass "node 2 replicated it"

echo "== resolver"
cat > blocklist.txt <<BL
# my own choice, on my machine
blocked.xyz
BL
"$BIN/dweb-resolver" --data-dir resolver --listen 127.0.0.1:17780 --sync-interval 1 \
  --blocklist blocklist.txt & PIDS+=($!)
wait_http http://127.0.0.1:17780/
PROXY=http://127.0.0.1:17780

curl -s -x "$PROXY" http://alice.xyz/ | grep -q "hello from alice" || fail "http via resolver"
pass "http://alice.xyz loads"
curl -s -x "$PROXY" --cacert resolver/ca.pem https://alice.xyz/ | grep -q "hello from alice" \
  || fail "https via resolver"
pass "https://alice.xyz loads, verified against the local CA and the site key"
if curl -s -x "$PROXY" https://alice.xyz/ -o /dev/null; then fail "https without CA should fail"; fi
pass "a browser without the local CA does not trust it"
curl -s -x "$PROXY" http://nobody.xyz/ | grep -q "not registered" || fail "unknown name page"
pass "unknown names give a clear error"

echo "== reverse proxy to a local service"
mkdir app && echo 'dynamic app says hi' > app/index.html
python3 -m http.server 17800 --bind 127.0.0.1 --directory app >/dev/null 2>&1 & PIDS+=($!)
# Claim the name with no server yet; the site server publishes itself.
"$BIN/dweb-wallet" register app.xyz --key alice.key >/dev/null 2>&1 || fail "register app.xyz"
"$BIN/dweb-site" --key app-site.key --proxy-to http://127.0.0.1:17800 --listen 127.0.0.1:17444 \
  --publish app.xyz --owner-key alice.key --public-address 127.0.0.1:17444 \
  --registry http://127.0.0.1:17701 & PIDS+=($!)
sleep 3
curl -s -x "$PROXY" http://app.xyz/ | grep -q "dynamic app says hi" || fail "reverse proxy"
pass "dweb-site --publish pointed app.xyz at itself; reverse proxy works"

echo "== genesis mint (cap 1)"
"$BIN/dweb-wallet" mint free.xyz --genesis-key genesis.key --owner "$BOB" >/dev/null || fail "mint"
"$BIN/dweb-wallet" lookup free.xyz | grep -q "by the genesis key" || fail "mint not tagged"
pass "minted free.xyz for bob, tagged admin-minted"
sleep 1.1 # ops in the same second are ordered by id; keep this one strictly later
if "$BIN/dweb-wallet" mint free2.xyz --genesis-key genesis.key --owner "$BOB" >/dev/null 2>&1; then
  fail "mint over cap should be refused"
fi
pass "second mint refused by the cap"
if "$BIN/dweb-wallet" transfer alice.xyz --key genesis.key --to "$BOB" >/dev/null 2>&1; then
  fail "genesis must not be able to take alice.xyz"
fi
pass "genesis key cannot transfer someone else's name"

echo "== blocklist"
"$BIN/dweb-wallet" register blocked.xyz --key bob.key --site-key "$SITE_KEY" \
  --address 127.0.0.1:17443 >/dev/null 2>&1 || fail "register blocked.xyz"
sleep 2
curl -s -x "$PROXY" http://blocked.xyz/ | grep -q "blocklist" || fail "blocklist"
pass "blocked.xyz is blocked by this resolver only"
"$BIN/dweb-wallet" --registry http://127.0.0.1:17702 lookup blocked.xyz | grep -q active \
  || fail "blocked.xyz should still exist on the network"
pass "...and still exists on the network"

echo "== impersonation"
"$BIN/dweb-wallet" keygen --out other.key >/dev/null 2>&1
OTHER=$("$BIN/dweb-wallet" pubkey other.key)
"$BIN/dweb-wallet" update alice.xyz --key alice.key --site-key "$OTHER" >/dev/null || fail "update"
sleep 2
curl -s -x "$PROXY" http://alice.xyz/ | grep -q "Site unavailable" || fail "wrong key accepted"
pass "server that cannot prove the registered key is refused"

echo "== renew and transfer"
"$BIN/dweb-wallet" renew alice.xyz --key alice.key >/dev/null || fail "renew"
"$BIN/dweb-wallet" transfer alice.xyz --key alice.key --to "$BOB" >/dev/null || fail "transfer"
"$BIN/dweb-wallet" lookup alice.xyz | grep -q "owner:       $BOB" || fail "transfer not applied"
if "$BIN/dweb-wallet" renew alice.xyz --key alice.key >/dev/null 2>&1; then fail "old owner still in control"; fi
pass "renewed, transferred, old owner locked out"

echo "== restart keeps the ledger"
kill "${PIDS[0]}"; wait "${PIDS[0]}" 2>/dev/null || true
"$BIN/dweb-node" --listen 127.0.0.1:17701 --data-dir node1 --sync-interval 1 & PIDS+=($!)
wait_http http://127.0.0.1:17701/v1/info
"$BIN/dweb-wallet" lookup free.xyz | grep -q active || fail "ledger lost on restart"
pass "node 1 reloaded its ledger"

echo "all end-to-end checks passed"
