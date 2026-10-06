//! Site server: serves a static site (or reverse-proxies a local service)
//! over TLS, proving it holds the site key the registry lists for the name.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use clap::Parser;
use dweb_net::client::RegistryClient;
use dweb_protocol::{NetworkConfig, Op, OpBody, SecretKey, Target, name, now_secs};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use tower_http::services::ServeDir;

#[derive(Parser)]
#[command(version, about = "Site server: serves a site over key-pinned TLS")]
struct Args {
    #[arg(long, default_value = "network.toml", env = "DWEB_CONFIG")]
    config: PathBuf,
    /// Site key file. Created on first run. This key lives on the server;
    /// the owner key does not need to.
    #[arg(long, default_value = "site.key")]
    key: PathBuf,
    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: SocketAddr,
    /// Directory of static files to serve.
    #[arg(long, conflicts_with = "proxy_to")]
    root: Option<PathBuf>,
    /// Reverse-proxy every request to this local HTTP service instead,
    /// e.g. http://127.0.0.1:3000.
    #[arg(long)]
    proxy_to: Option<String>,
    /// Print the site's public key and exit.
    #[arg(long)]
    print_key: bool,

    /// Publish this server in the registry: the name to point here.
    #[arg(long, requires_all = ["owner_key", "public_address"])]
    publish: Option<String>,
    /// Owner key of the name, needed only with --publish.
    #[arg(long)]
    owner_key: Option<PathBuf>,
    /// Address visitors reach this server on (ip:port or x.onion:port).
    #[arg(long)]
    public_address: Option<String>,
    /// Registry node to publish to (default: first bootstrap node).
    #[arg(long)]
    registry: Option<String>,
}

fn load_or_create_key(path: &Path) -> Result<SecretKey> {
    if path.exists() {
        let text = std::fs::read_to_string(path)?;
        return Ok(SecretKey::from_file_string(&text)?);
    }
    let key = SecretKey::generate()?;
    dweb_net::write_private_file(path, key.to_file_string().as_bytes())
        .with_context(|| format!("cannot write {}", path.display()))?;
    tracing::info!("created new site key {}", path.display());
    Ok(key)
}

/// Points the name at this server if the registry says otherwise.
async fn publish(args: &Args, cfg: &NetworkConfig, site_key: &SecretKey) -> Result<()> {
    let name = name::normalize(args.publish.as_deref().unwrap_or_default(), &cfg.name_rules)?;
    let owner_path = args.owner_key.as_ref().expect("required by clap");
    let owner = SecretKey::from_file_string(&std::fs::read_to_string(owner_path)?)?;
    let registry = args
        .registry
        .clone()
        .or_else(|| cfg.bootstrap_nodes.first().cloned())
        .context("no registry given and no bootstrap_nodes in config")?;
    let client = RegistryClient::new(&cfg.transport)?;
    let info = client
        .name(&registry, &name)
        .await?
        .filter(|i| i.active)
        .with_context(|| format!("{name} is not registered"))?;
    if info.record.owner != owner.public() {
        bail!("{} is not the owner of {name}", owner_path.display());
    }
    let target = Target {
        site_key: Some(site_key.public()),
        address: args.public_address.clone(),
    };
    if info.record.target == target {
        tracing::info!("registry already points {name} here");
        return Ok(());
    }
    let body = OpBody::Update {
        name: name.clone(),
        seq: info.record.seq + 1,
        target,
    };
    let cfg2 = cfg.clone();
    let op = tokio::task::spawn_blocking(move || Op::create(&cfg2, now_secs(), body, Some(&owner)))
        .await??;
    let resp = client.submit(&registry, &op).await?;
    tracing::info!("published {name} -> this server ({:?})", resp.status);
    Ok(())
}

#[derive(Clone)]
struct Proxy {
    upstream: String,
    http: reqwest::Client,
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
    "host",
];

fn copy_headers(from: &HeaderMap, to: &mut HeaderMap) {
    for (k, v) in from {
        if !HOP_BY_HOP.contains(&k.as_str()) {
            to.append(k.clone(), v.clone());
        }
    }
}

async fn proxy_handler(State(p): State<Proxy>, req: Request) -> Response {
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let url = format!("{}{}", p.upstream.trim_end_matches('/'), path);
    let method = req.method().clone();
    let mut headers = HeaderMap::new();
    copy_headers(req.headers(), &mut headers);
    let body = match axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let resp = match p
        .http
        .request(method, url)
        .headers(headers)
        .body(body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("upstream error: {e}");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    let status = resp.status();
    let mut out_headers = HeaderMap::new();
    copy_headers(resp.headers(), &mut out_headers);
    let bytes = resp.bytes().await.unwrap_or_default();
    let mut out = Response::new(Body::from(bytes));
    *out.status_mut() = status;
    *out.headers_mut() = out_headers;
    out
}

#[tokio::main]
async fn main() -> Result<()> {
    dweb_net::init();
    let args = Args::parse();
    let site_key = load_or_create_key(&args.key)?;
    if args.print_key {
        println!("{}", site_key.public());
        return Ok(());
    }
    let cfg = NetworkConfig::load(&args.config)?;

    let app = match (&args.root, &args.proxy_to) {
        (Some(root), None) => {
            if !root.is_dir() {
                bail!("{} is not a directory", root.display());
            }
            Router::new()
                .fallback_service(ServeDir::new(root).append_index_html_on_directories(true))
        }
        (None, Some(upstream)) => {
            let http = reqwest::Client::builder().no_proxy().build()?;
            Router::new().fallback(proxy_handler).with_state(Proxy {
                upstream: upstream.clone(),
                http,
            })
        }
        _ => bail!("give either --root DIR or --proxy-to URL"),
    };

    if args.publish.is_some() {
        publish(&args, &cfg, &site_key).await?;
    }

    let acceptor = tokio_rustls::TlsAcceptor::from(dweb_net::tls::site_server_config(&site_key)?);
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(
        "serving on {} with site key {}",
        listener.local_addr()?,
        site_key.public()
    );
    let app = Arc::new(app);
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = (*app).clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!("TLS handshake with {peer} failed: {e}");
                    return;
                }
            };
            let svc = TowerToHyperService::new(app);
            let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            if let Err(e) = builder.serve_connection(TokioIo::new(tls), svc).await {
                tracing::debug!("connection from {peer} ended: {e}");
            }
        });
    }
}
