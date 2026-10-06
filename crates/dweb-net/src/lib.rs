//! Networking for the decentralised web: the registry HTTP API, ledger
//! storage and sync, overlay transports, and key-pinned TLS.
//!
//! The binaries in `src/bin` are the registry node (`dweb-node`), the local
//! resolver (`dweb-resolver`) and the site server (`dweb-site`).

pub mod api;
pub mod client;
pub mod store;
pub mod sync;
pub mod tls;
pub mod transport;

use std::path::PathBuf;

/// Sets up logging and the TLS crypto provider. Call once at startup.
pub fn init() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

/// Default data directory for a program, e.g. `~/.local/share/dweb/resolver`.
pub fn default_data_dir(program: &str) -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("dweb").join(program)
}

/// Writes a secret file readable only by the current user.
pub fn write_private_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    let mut f = opts.open(path)?;
    f.write_all(contents)?;
    f.sync_all()
}
