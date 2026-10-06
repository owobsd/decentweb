//! Resolver: a local HTTP proxy on 127.0.0.1. For each name the browser
//! visits it looks the name up in its own copy of the ledger, connects to the
//! owner's server (over Tor or I2P if configured), checks the server holds the
//! registered site key, and only then lets the page load.
//!
//! The resolver keeps a full copy of the ledger synced from registry nodes,
//! so it never has to trust a single node's answer about who owns a name.

use std::collections::HashSet;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::Parser;
use dweb_net::client::RegistryClient;
use dweb_net::store::Store;
use dweb_net::sync::Syncer;
use dweb_net::tls::LocalCa;
use dweb_protocol::{NetworkConfig, PublicKey, name, now_secs};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::{CONTENT_TYPE, HOST, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

#[derive(Parser)]
#[command(
    version,
    about = "Local resolver: lets a browser visit names on the network"
)]
struct Args {
    #[arg(long, default_value = "network.toml", env = "DWEB_CONFIG")]
    config: PathBuf,
    /// Proxy address. Must be a loopback address.
    #[arg(long, default_value = "127.0.0.1:7780")]
    listen: SocketAddr,
    /// Where to keep the ledger copy and the local certificate authority.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Extra registry nodes to sync from, besides the bootstrap nodes.
    #[arg(long = "registry")]
    registries: Vec<String>,
    /// Blocklist files: one name per line, `#` for comments. Blocking is a
    /// choice made here, on your machine; the network never removes names.
    #[arg(long = "blocklist")]
    blocklists: Vec<PathBuf>,
    /// Seconds between ledger sync rounds.
    #[arg(long, default_value_t = 15)]
    sync_interval: u64,
    /// Write the local CA certificate to this path and exit (for installers).
    #[arg(long)]
    export_ca: Option<PathBuf>,
}

type Body = BoxBody<Bytes, hyper::Error>;

struct Ctx {
    cfg: NetworkConfig,
    store: Arc<Store>,
    ca: LocalCa,
    blocked: HashSet<String>,
    socks: Option<String>,
    listen: SocketAddr,
}

struct Site {
    name: String,
    site_key: PublicKey,
    address: String,
}

fn full(text: impl Into<Bytes>) -> Body {
    Full::new(text.into()).map_err(|n| match n {}).boxed()
}

fn empty() -> Body {
    Empty::<Bytes>::new().map_err(|n| match n {}).boxed()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn error_page(status: StatusCode, title: &str, detail: &str) -> Response<Body> {
    let html = format!(
        "<!doctype html><meta charset=utf-8><title>{t}</title>\
         <style>body{{font:16px system-ui,sans-serif;max-width:40em;margin:4em auto;padding:0 1em}}</style>\
         <h1>{t}</h1><p>{d}</p><p><small>dweb resolver</small></p>",
        t = html_escape(title),
        d = html_escape(detail)
    );
    let mut r = Response::new(full(html));
    *r.status_mut() = status;
    r.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    r
}

impl Ctx {
    /// Finds where `host` lives, or explains why it cannot be visited.
    fn resolve(&self, host: &str) -> std::result::Result<Site, (StatusCode, String, String)> {
        let not_found = |why: String| (StatusCode::NOT_FOUND, "Name not found".to_string(), why);
        let name = name::normalize(host, &self.cfg.name_rules)
            .map_err(|e| not_found(format!("{host} is not a valid name on this network: {e}")))?;
        if self.blocked.contains(&name) {
            return Err((
                StatusCode::FORBIDDEN,
                "Blocked by your blocklist".into(),
                format!("{name} is on a blocklist this resolver was started with."),
            ));
        }
        let record = self
            .store
            .read(|l| l.lookup(&name, now_secs()).cloned())
            .ok_or_else(|| not_found(format!("{name} is not registered, or has expired.")))?;
        let (Some(site_key), Some(address)) = (record.target.site_key, record.target.address)
        else {
            return Err(not_found(format!(
                "{name} is registered but does not point at a server yet."
            )));
        };
        Ok(Site {
            name,
            site_key,
            address,
        })
    }

    /// Connects to the site and verifies it holds the registered key.
    async fn connect(&self, site: &Site) -> Result<TlsStream<TcpStream>> {
        let tcp = dweb_net::transport::connect(&site.address, self.socks.as_deref()).await?;
        dweb_net::tls::connect_pinned(tcp, &site.name, site.site_key).await
    }
}

fn host_of(req: &Request<Incoming>) -> Option<String> {
    req.uri().host().map(str::to_string).or_else(|| {
        req.headers()
            .get(HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.rsplit_once(':').map(|(h, _)| h).unwrap_or(h).to_string())
    })
}

async fn handle(req: Request<Incoming>, ctx: Arc<Ctx>) -> Result<Response<Body>, Infallible> {
    if req.method() == Method::CONNECT {
        return Ok(handle_connect(req, ctx));
    }
    // A request for the proxy itself, e.g. http://127.0.0.1:7780/ca.pem.
    if req.uri().authority().is_none() {
        return Ok(local_page(&req, &ctx));
    }
    Ok(match forward_http(req, &ctx).await {
        Ok(r) => r,
        Err(r) => r,
    })
}

fn local_page(req: &Request<Incoming>, ctx: &Ctx) -> Response<Body> {
    if req.uri().path() == "/ca.pem" {
        let mut r = Response::new(full(ctx.ca.cert_pem().to_string()));
        r.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-pem-file"),
        );
        return r;
    }
    let (ops, names) = ctx
        .store
        .read(|l| (l.len(), l.active_names(now_secs()).count()));
    error_page(
        StatusCode::OK,
        "dweb resolver is running",
        &format!(
            "Network {} ({}). Ledger: {ops} operations, {names} active names. \
             Proxy: {}. Local CA certificate: /ca.pem",
            ctx.cfg.network_name,
            ctx.cfg.network_id(),
            ctx.listen
        ),
    )
}

/// HTTPS: the browser asks for a tunnel. We terminate its TLS with a
/// certificate from the local CA and splice it onto a key-pinned TLS
/// connection to the site.
fn handle_connect(req: Request<Incoming>, ctx: Arc<Ctx>) -> Response<Body> {
    let Some(host) = req.uri().host().map(str::to_string) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Bad request",
            "CONNECT without a host",
        );
    };
    let name = match name::normalize(&host, &ctx.cfg.name_rules) {
        Ok(n) => n,
        Err(e) => return error_page(StatusCode::NOT_FOUND, "Name not found", &e.to_string()),
    };
    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(req).await {
            Ok(u) => TokioIo::new(u),
            Err(e) => {
                tracing::debug!("upgrade failed: {e}");
                return;
            }
        };
        let tls_cfg = match ctx.ca.server_config(&name) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("local CA error: {e:#}");
                return;
            }
        };
        let mut browser = match tokio_rustls::TlsAcceptor::from(tls_cfg)
            .accept(upgraded)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("browser TLS failed for {name}: {e} (is the local CA installed?)");
                return;
            }
        };
        let site = match ctx.resolve(&name) {
            Ok(s) => s,
            Err((code, title, detail)) => {
                return serve_error(browser, code, title, detail).await;
            }
        };
        let mut upstream = match ctx.connect(&site).await {
            Ok(s) => s,
            Err(e) => {
                tracing::info!("{name}: {e:#}");
                let detail = format!(
                    "Could not reach {name} at {}, or the server could not prove it holds \
                     the site key listed in the registry, so the page was not loaded. ({e:#})",
                    site.address
                );
                return serve_error(
                    browser,
                    StatusCode::BAD_GATEWAY,
                    "Site unavailable".into(),
                    detail,
                )
                .await;
            }
        };
        let _ = tokio::io::copy_bidirectional(&mut browser, &mut upstream).await;
    });
    Response::new(empty())
}

async fn serve_error<S>(stream: S, code: StatusCode, title: String, detail: String)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |_req: Request<Incoming>| {
        let r = error_page(code, &title, &detail);
        async move { Ok::<_, Infallible>(r) }
    });
    let _ = http1::Builder::new()
        .keep_alive(false)
        .serve_connection(TokioIo::new(stream), svc)
        .await;
}

/// Plain `http://name/` requests from the browser. The hop from the browser
/// to this proxy stays on the local machine; the hop to the site is always
/// TLS-encrypted and key-pinned.
async fn forward_http(
    mut req: Request<Incoming>,
    ctx: &Ctx,
) -> std::result::Result<Response<Body>, Response<Body>> {
    let host = host_of(&req)
        .ok_or_else(|| error_page(StatusCode::BAD_REQUEST, "Bad request", "no host"))?;
    let site = ctx
        .resolve(&host)
        .map_err(|(code, title, detail)| error_page(code, &title, &detail))?;
    let tls = ctx.connect(&site).await.map_err(|e| {
        error_page(
            StatusCode::BAD_GATEWAY,
            "Site unavailable",
            &format!("Could not reach {} or verify its key: {e:#}", site.name),
        )
    })?;
    let bad_gateway =
        |e: hyper::Error| error_page(StatusCode::BAD_GATEWAY, "Site error", &e.to_string());
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(bad_gateway)?;
    tokio::spawn(conn);

    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    *req.uri_mut() = path
        .parse::<Uri>()
        .unwrap_or_else(|_| Uri::from_static("/"));
    let headers = req.headers_mut();
    headers.remove("proxy-connection");
    headers.remove("proxy-authorization");
    headers.insert(
        HOST,
        HeaderValue::from_str(&site.name).expect("names are valid headers"),
    );
    let resp = sender.send_request(req).await.map_err(bad_gateway)?;
    Ok(resp.map(|b| b.boxed()))
}

fn load_blocklists(paths: &[PathBuf], cfg: &NetworkConfig) -> Result<HashSet<String>> {
    let mut set = HashSet::new();
    for p in paths {
        let text =
            std::fs::read_to_string(p).with_context(|| format!("cannot read {}", p.display()))?;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            match name::normalize(line, &cfg.name_rules) {
                Ok(n) => {
                    set.insert(n);
                }
                Err(e) => tracing::warn!("{}: ignoring {line:?}: {e}", p.display()),
            }
        }
    }
    Ok(set)
}

#[tokio::main]
async fn main() -> Result<()> {
    dweb_net::init();
    let args = Args::parse();
    if !args.listen.ip().is_loopback() {
        bail!("the resolver only listens on a loopback address (127.0.0.1 or ::1)");
    }
    let cfg = NetworkConfig::load(&args.config)?;
    let data_dir = args
        .data_dir
        .clone()
        .unwrap_or_else(|| dweb_net::default_data_dir("resolver"));
    std::fs::create_dir_all(&data_dir)?;
    let ca = LocalCa::load_or_create(&data_dir)?;
    if let Some(path) = &args.export_ca {
        std::fs::write(path, ca.cert_pem())?;
        println!("wrote {}", path.display());
        return Ok(());
    }

    let store = Arc::new(Store::open(
        cfg.clone(),
        Some(&data_dir.join(&cfg.network_name)),
    )?);
    let client = RegistryClient::new(&cfg.transport)?;
    let mut registries = cfg.bootstrap_nodes.clone();
    registries.extend(args.registries.clone());
    let mut syncer = Syncer::new(store.clone(), client, registries, None);
    if syncer.round().await == 0 {
        tracing::warn!("no registry node reachable yet; using the local ledger copy");
    }
    tokio::spawn(syncer.run(Duration::from_secs(args.sync_interval.max(1))));

    let ctx = Arc::new(Ctx {
        blocked: load_blocklists(&args.blocklists, &cfg)?,
        socks: cfg.transport.socks_proxy(),
        cfg,
        store,
        ca,
        listen: args.listen,
    });
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(
        "resolver proxy on {} ({} names blocked locally, transport {:?}); CA certificate at {}",
        listener.local_addr()?,
        ctx.blocked.len(),
        ctx.cfg.transport.mode,
        data_dir.join("ca.pem").display()
    );
    loop {
        let (tcp, _) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| handle(req, ctx.clone()));
            if let Err(e) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(TokioIo::new(tcp), svc)
                .with_upgrades()
                .await
            {
                tracing::debug!("proxy connection ended: {e}");
            }
        });
    }
}
