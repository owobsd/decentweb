//! Wallet and command-line tool: generates keys and registers, updates,
//! renews and transfers names.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use dweb_net::client::RegistryClient;
use dweb_protocol::op::commitment;
use dweb_protocol::{
    Hash, NetworkConfig, Op, OpBody, OpStatus, PublicKey, SecretKey, Target, name, now_secs, pow,
};
use serde::{Deserialize, Serialize};

const BACKUP_WARNING: &str = "\
IMPORTANT: this key file IS your ownership. Whoever holds it owns your names,
and if you lose it your names cannot be recovered by anyone: they will simply
expire. There is no support desk and no reset. Back it up now, somewhere
offline, and never share it.";

#[derive(Parser)]
#[command(version, about = "Wallet: keys and names on the decentralised web")]
struct Cli {
    #[arg(
        long,
        global = true,
        default_value = "network.toml",
        env = "DWEB_CONFIG"
    )]
    config: PathBuf,
    /// Registry node to talk to (default: first bootstrap node).
    #[arg(long, global = true, env = "DWEB_REGISTRY")]
    registry: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new key (owner key, genesis key or site key).
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the public key of a key file.
    Pubkey { key: PathBuf },
    /// Print this network's ID.
    NetworkId,
    /// Show who owns a name and where it points.
    Lookup { name: String },
    /// Claim an unused name with proof-of-work (commit, wait, reveal).
    Register {
        name: String,
        /// Owner key file.
        #[arg(long)]
        key: PathBuf,
        #[command(flatten)]
        target: TargetArgs,
    },
    /// Change the server a name points at.
    Update {
        name: String,
        #[arg(long)]
        key: PathBuf,
        #[command(flatten)]
        target: TargetArgs,
    },
    /// Extend a name's expiry.
    Renew {
        name: String,
        #[arg(long)]
        key: PathBuf,
    },
    /// Hand a name to another key. This cannot be undone.
    Transfer {
        name: String,
        #[arg(long)]
        key: PathBuf,
        /// New owner's public key (hex).
        #[arg(long)]
        to: PublicKey,
    },
    /// Genesis key only: mint a free name for an owner, without proof-of-work.
    Mint {
        name: String,
        /// The genesis key file.
        #[arg(long)]
        genesis_key: PathBuf,
        /// Public key that will own the name.
        #[arg(long)]
        owner: PublicKey,
        #[command(flatten)]
        target: TargetArgs,
    },
}

#[derive(clap::Args)]
struct TargetArgs {
    /// Site key (hex public key the site server proves it holds).
    /// See `dweb-site --print-key`.
    #[arg(long)]
    site_key: Option<PublicKey>,
    /// Server address: ip:port, [ipv6]:port, or x.onion:port.
    #[arg(long)]
    address: Option<String>,
}

impl TargetArgs {
    fn target(&self) -> Result<Target> {
        let t = Target {
            site_key: self.site_key,
            address: self.address.clone(),
        };
        t.validate()?;
        Ok(t)
    }
}

/// Saved between the commit and reveal steps so an interrupted registration
/// can resume without redoing the commit.
#[derive(Serialize, Deserialize)]
struct Pending {
    name: String,
    salt: Hash,
    commit: Op,
}

struct Wallet {
    cfg: NetworkConfig,
    registry: String,
    client: RegistryClient,
}

fn read_key(path: &Path) -> Result<SecretKey> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read key file {}", path.display()))?;
    Ok(SecretKey::from_file_string(&text)?)
}

fn fmt_time(t: u64) -> String {
    let now = now_secs();
    let days = |s: u64| s as f64 / 86_400.0;
    if t >= now {
        format!("{t} (in {:.1} days)", days(t - now))
    } else {
        format!("{t} ({:.1} days ago)", days(now - t))
    }
}

impl Wallet {
    /// Builds and submits an operation, doing its proof-of-work first.
    async fn send(&self, body: OpBody, key: Option<&SecretKey>) -> Result<(Op, Option<OpStatus>)> {
        let cfg = self.cfg.clone();
        let key = key.cloned();
        let bits = body.pow_bits(&cfg);
        if bits >= 16 {
            eprintln!(
                "doing proof-of-work: {bits} bits (about {:.0} hashes)...",
                pow::expected_hashes(bits)
            );
        }
        let op =
            tokio::task::spawn_blocking(move || Op::create(&cfg, now_secs(), body, key.as_ref()))
                .await??;
        let resp = self
            .client
            .submit(&self.registry, &op)
            .await
            .with_context(|| format!("submitting to {}", self.registry))?;
        Ok((op, resp.status))
    }

    fn report(&self, what: &str, status: Option<OpStatus>) -> Result<()> {
        match status {
            Some(OpStatus::Applied) => {
                println!("{what}: done");
                Ok(())
            }
            Some(OpStatus::Rejected { reason }) => bail!("{what} was refused: {reason}"),
            None => bail!("{what}: the registry did not report a result"),
        }
    }

    fn name(&self, n: &str) -> Result<String> {
        Ok(name::normalize(n, &self.cfg.name_rules)?)
    }

    /// The active record for `name`, checking `key` owns it.
    async fn owned(&self, n: &str, key: &SecretKey) -> Result<dweb_protocol::NameRecord> {
        let info = self
            .client
            .name(&self.registry, n)
            .await?
            .filter(|i| i.active)
            .with_context(|| format!("{n} is not registered (or has expired)"))?;
        if info.record.owner != key.public() {
            bail!("this key ({}) does not own {n}", key.public());
        }
        Ok(info.record)
    }

    async fn register(&self, n: &str, key_path: &Path, target: Target) -> Result<()> {
        let key = read_key(key_path)?;
        let n = self.name(n)?;
        if let Some(info) = self.client.name(&self.registry, &n).await?
            && info.active
        {
            bail!(
                "{n} is already registered (expires {})",
                fmt_time(info.record.expires_at)
            );
        }
        let rules = &self.cfg.registration;
        let pending_path = key_path.with_extension(format!("pending-{n}.json"));

        let pending = match std::fs::read_to_string(&pending_path)
            .ok()
            .and_then(|s| serde_json::from_str::<Pending>(&s).ok())
            .filter(|p| p.name == n && now_secs() < p.commit.timestamp + rules.reveal_window_secs)
        {
            Some(p) => {
                println!("resuming registration from {}", pending_path.display());
                // Make sure the registry has the commit (it may have been restarted).
                let _ = self.client.submit(&self.registry, &p.commit).await;
                p
            }
            None => {
                let mut salt = [0u8; 32];
                getrandom::fill(&mut salt).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
                let salt = Hash(salt);
                let c = commitment(&self.cfg.network_id(), &n, &key.public(), &salt);
                println!("step 1/2: publishing a hidden commitment to the name");
                let (commit, status) = self.send(OpBody::Commit { commitment: c }, None).await?;
                self.report("commit", status)?;
                let p = Pending {
                    name: n.clone(),
                    salt,
                    commit,
                };
                std::fs::write(&pending_path, serde_json::to_string_pretty(&p)?)?;
                p
            }
        };

        let reveal_at = pending.commit.timestamp + rules.reveal_min_delay_secs + 1;
        while now_secs() < reveal_at {
            let left = reveal_at - now_secs();
            eprint!("\rwaiting {left}s before revealing (so nobody can race you to it)...   ");
            tokio::time::sleep(Duration::from_secs(left.min(5))).await;
        }
        eprintln!();

        println!(
            "step 2/2: revealing {n} (proof-of-work: {} bits)",
            self.cfg.name_pow_bits(&n)
        );
        let body = OpBody::Reveal {
            commit: pending.commit.id(),
            name: n.clone(),
            owner: key.public(),
            salt: pending.salt,
            target,
        };
        let (_, status) = self.send(body, Some(&key)).await?;
        self.report("reveal", status)?;
        let _ = std::fs::remove_file(&pending_path);
        self.lookup(&n).await?;
        println!(
            "\nRemember: back up {}. Lost keys mean lost names.",
            key_path.display()
        );
        Ok(())
    }

    async fn lookup(&self, n: &str) -> Result<()> {
        let n = self.name(n)?;
        match self.client.name(&self.registry, &n).await? {
            None => println!("{n}: not registered"),
            Some(info) => {
                let r = info.record;
                println!("name:        {}", r.name);
                println!(
                    "status:      {}",
                    if info.active { "active" } else { "expired" }
                );
                println!("owner:       {}", r.owner);
                println!(
                    "site key:    {}",
                    r.target
                        .site_key
                        .map(|k| k.to_hex())
                        .unwrap_or_else(|| "-".into())
                );
                println!(
                    "address:     {}",
                    r.target.address.as_deref().unwrap_or("-")
                );
                println!("registered:  {}", fmt_time(r.registered_at));
                println!("expires:     {}", fmt_time(r.expires_at));
                println!("seq:         {}", r.seq);
                if r.admin_minted {
                    println!("minted:      free, by the genesis key");
                }
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dweb_net::init();
    let cli = Cli::parse();

    match &cli.cmd {
        Cmd::Keygen { out } => {
            if out.exists() {
                bail!(
                    "{} already exists; refusing to overwrite a key",
                    out.display()
                );
            }
            let key = SecretKey::generate()?;
            dweb_net::write_private_file(out, key.to_file_string().as_bytes())?;
            println!("wrote {}", out.display());
            println!("public key: {}", key.public());
            eprintln!("\n{BACKUP_WARNING}");
            return Ok(());
        }
        Cmd::Pubkey { key } => {
            println!("{}", read_key(key)?.public());
            return Ok(());
        }
        _ => {}
    }

    let cfg = NetworkConfig::load(&cli.config)?;
    if let Cmd::NetworkId = cli.cmd {
        println!("{}", cfg.network_id());
        return Ok(());
    }
    let registry = cli
        .registry
        .clone()
        .or_else(|| cfg.bootstrap_nodes.first().cloned())
        .context("no --registry given and no bootstrap_nodes in the config")?;
    let w = Wallet {
        client: RegistryClient::new(&cfg.transport)?,
        cfg,
        registry,
    };

    match cli.cmd {
        Cmd::Keygen { .. } | Cmd::Pubkey { .. } | Cmd::NetworkId => unreachable!(),
        Cmd::Lookup { name } => w.lookup(&name).await,
        Cmd::Register { name, key, target } => w.register(&name, &key, target.target()?).await,
        Cmd::Update { name, key, target } => {
            let k = read_key(&key)?;
            let n = w.name(&name)?;
            let rec = w.owned(&n, &k).await?;
            let mut t = target.target()?;
            // Keep whichever half was not given.
            t.site_key = t.site_key.or(rec.target.site_key);
            t.address = t.address.or(rec.target.address);
            let (_, s) = w
                .send(
                    OpBody::Update {
                        name: n,
                        seq: rec.seq + 1,
                        target: t,
                    },
                    Some(&k),
                )
                .await?;
            w.report("update", s)
        }
        Cmd::Renew { name, key } => {
            let k = read_key(&key)?;
            let n = w.name(&name)?;
            let rec = w.owned(&n, &k).await?;
            let (_, s) = w
                .send(
                    OpBody::Renew {
                        name: n.clone(),
                        seq: rec.seq + 1,
                    },
                    Some(&k),
                )
                .await?;
            w.report("renew", s)?;
            w.lookup(&n).await
        }
        Cmd::Transfer { name, key, to } => {
            to.validate()?;
            let k = read_key(&key)?;
            let n = w.name(&name)?;
            let rec = w.owned(&n, &k).await?;
            let (_, s) = w
                .send(
                    OpBody::Transfer {
                        name: n,
                        seq: rec.seq + 1,
                        new_owner: to,
                    },
                    Some(&k),
                )
                .await?;
            w.report("transfer", s)
        }
        Cmd::Mint {
            name,
            genesis_key,
            owner,
            target,
        } => {
            let k = read_key(&genesis_key)?;
            match w.cfg.genesis_public_key()? {
                None => bail!("this network has no genesis key"),
                Some(g) if g != k.public() => bail!(
                    "{} is not this network's genesis key",
                    genesis_key.display()
                ),
                Some(_) => {}
            }
            owner.validate()?;
            let n = w.name(&name)?;
            let (_, s) = w
                .send(
                    OpBody::Mint {
                        name: n.clone(),
                        owner,
                        target: target.target()?,
                    },
                    Some(&k),
                )
                .await?;
            w.report("mint", s)?;
            w.lookup(&n).await
        }
    }
}
