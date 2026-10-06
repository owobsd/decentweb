#!/bin/sh
# Installs the dweb resolver and a dedicated LibreWolf profile (Linux, macOS).
#
# Run from an unpacked release folder containing bin/, network.toml and
# browser/. What it does:
#   1. copies the programs and network.toml to ~/.local/share/dweb
#   2. runs the resolver as a background service on 127.0.0.1:7780
#   3. creates a LibreWolf profile that sends all traffic to the resolver and
#      trusts the resolver's local certificate authority (this profile only)
#   4. adds a `dweb-browser` launcher
#
# Uninstall: stop and remove the service (dweb-resolver), then delete
# ~/.local/share/dweb and ~/.local/bin/dweb-browser.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(cd "$HERE/.." && pwd)"
DEST="${DWEB_HOME:-$HOME/.local/share/dweb}"
BIN_DIR="$HOME/.local/bin"
PROFILE="$DEST/librewolf-profile"
DATA="$DEST/resolver"
OS="$(uname -s)"

say() { printf '%s\n' "$*"; }

find_bin() {
  for d in "$SRC/bin" "$SRC/target/release"; do
    [ -x "$d/$1" ] && { printf '%s\n' "$d/$1"; return 0; }
  done
  command -v "$1" 2>/dev/null && return 0
  say "cannot find $1; build with 'cargo build --release' or use a release bundle" >&2
  exit 1
}

mkdir -p "$DEST/bin" "$BIN_DIR" "$DATA"
for b in dweb-resolver dweb-wallet dweb-site dweb-node; do
  cp "$(find_bin "$b")" "$DEST/bin/$b"
done
[ -f "$DEST/network.toml" ] || cp "$SRC/network.toml" "$DEST/network.toml"
say "installed programs to $DEST/bin"

RESOLVER="$DEST/bin/dweb-resolver --config $DEST/network.toml --data-dir $DATA"

# 1. Local certificate authority (created on first run, never leaves this machine).
$RESOLVER --export-ca "$DEST/ca.pem" >/dev/null

# 2. Background service.
case "$OS" in
  Linux)
    UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    mkdir -p "$UNIT_DIR"
    cat > "$UNIT_DIR/dweb-resolver.service" <<UNIT
[Unit]
Description=dweb local resolver
After=network-online.target

[Service]
ExecStart=$RESOLVER
Restart=on-failure

[Install]
WantedBy=default.target
UNIT
    if command -v systemctl >/dev/null && systemctl --user daemon-reload 2>/dev/null; then
      systemctl --user enable --now dweb-resolver.service
      say "resolver running as systemd user service dweb-resolver"
    else
      say "systemd not available: start the resolver yourself with:"
      say "  $RESOLVER"
    fi
    ;;
  Darwin)
    PLIST="$HOME/Library/LaunchAgents/org.dweb.resolver.plist"
    mkdir -p "$(dirname "$PLIST")"
    cat > "$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>org.dweb.resolver</string>
  <key>ProgramArguments</key><array>
    <string>$DEST/bin/dweb-resolver</string>
    <string>--config</string><string>$DEST/network.toml</string>
    <string>--data-dir</string><string>$DATA</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
PL
    launchctl unload "$PLIST" 2>/dev/null || true
    launchctl load "$PLIST"
    say "resolver running as launchd agent org.dweb.resolver"
    ;;
  *) say "unknown OS $OS: start the resolver yourself: $RESOLVER" ;;
esac

# 3. Browser profile.
mkdir -p "$PROFILE"
cp "$HERE/user.js" "$PROFILE/user.js"
if command -v certutil >/dev/null; then
  [ -f "$PROFILE/cert9.db" ] || certutil -N --empty-password -d "sql:$PROFILE"
  certutil -D -n "dweb local resolver CA" -d "sql:$PROFILE" 2>/dev/null || true
  certutil -A -n "dweb local resolver CA" -t "C,," -i "$DEST/ca.pem" -d "sql:$PROFILE"
  say "local CA trusted in the dweb profile only"
else
  say "certutil (NSS tools) not found. Install it (Debian/Ubuntu: libnss3-tools,"
  say "Fedora: nss-tools, macOS: brew install nss) and re-run, or import"
  say "$DEST/ca.pem by hand in the dweb browser: Settings > Privacy & Security >"
  say "Certificates > View Certificates > Authorities > Import (trust for websites)."
fi

# 4. Launcher.
LW=""
for c in librewolf /Applications/LibreWolf.app/Contents/MacOS/librewolf; do
  if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then LW="$c"; break; fi
done
cat > "$BIN_DIR/dweb-browser" <<SH
#!/bin/sh
# Opens LibreWolf with the dedicated dweb profile.
exec ${LW:-librewolf} --no-remote --profile "$PROFILE" "\$@"
SH
chmod +x "$BIN_DIR/dweb-browser"
[ -n "$LW" ] || say "LibreWolf not found: install it from https://librewolf.net, then run dweb-browser"

say ""
say "Done. Run 'dweb-browser' and type a name such as alice.xyz."
say "Your normal browser is unchanged."
