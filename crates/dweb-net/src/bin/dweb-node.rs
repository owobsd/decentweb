//! Registry node: stores the full ledger, validates every operation, serves
//! the registry API and replicates with other nodes.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use dweb_net::api::{ErrorBody, Info, NameInfo, OpInfo, OpsPage, SubmitResponse};
use dweb_net::client::RegistryClient;
use dweb_net::store::{Origin, Store};
use dweb_net::sync::Syncer;
use dweb_protocol::{Hash, NetworkConfig, Op, now_secs};
use serde::Deserialize;

#[derive(Parser)]
#[command(version, about = "Registry node: holds and replicates the name ledger")]
struct Args {
    /// Path to the network config.
    #[arg(long, default_value = "network.toml", env = "DWEB_CONFIG")]
    config: PathBuf,
    /// Address to serve the registry API on.
    #[arg(long, default_value = "127.0.0.1:7700")]
    listen: SocketAddr,
    /// Where to keep the ledger.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Extra peers to replicate with, besides the config's bootstrap nodes.
    #[arg(long = "peer")]
    peers: Vec<String>,
    /// Seconds between sync rounds.
    #[arg(long, default_value_t = 10)]
    sync_interval: u64,
}

struct AppState {
    store: Arc<Store>,
    node_id: String,
    network_name: String,
    client: RegistryClient,
    peers: Vec<String>,
}

type Shared = Arc<AppState>;

fn error(code: StatusCode, msg: impl ToString) -> Response {
    (
        code,
        Json(ErrorBody {
            error: msg.to_string(),
        }),
    )
        .into_response()
}

async fn info(State(s): State<Shared>) -> Json<Info> {
    let now = now_secs();
    let (network_id, ops, active_names, admin_minted) = s.store.read(|l| {
        (
            l.network_id(),
            l.len(),
            l.active_names(now).count(),
            l.admin_minted_count(),
        )
    });
    Json(Info {
        network_name: s.network_name.clone(),
        network_id,
        node_id: s.node_id.clone(),
        ops,
        active_names,
        admin_minted,
    })
}

async fn submit(State(s): State<Shared>, Json(op): Json<Op>) -> Response {
    let store = s.store.clone();
    let relay = op.clone();
    let res = tokio::task::spawn_blocking(move || store.add(op, Origin::Local, now_secs())).await;
    match res {
        Ok(Ok((id, new))) => {
            if new {
                // Push to peers right away; pull-sync covers any that miss it.
                for peer in s.peers.clone() {
                    let (client, op) = (s.client.clone(), relay.clone());
                    tokio::spawn(async move {
                        if let Err(e) = client.submit(&peer, &op).await {
                            tracing::debug!("relay to {peer} failed: {e:#}");
                        }
                    });
                }
                tracing::info!("accepted {} {}", relay.body.kind(), id);
            }
            let status = s.store.read(|l| l.status(&id).cloned());
            Json(SubmitResponse { id, new, status }).into_response()
        }
        Ok(Err(e)) => error(StatusCode::BAD_REQUEST, e),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

#[derive(Deserialize)]
struct OpsQuery {
    #[serde(default)]
    from: usize,
    limit: Option<usize>,
}

async fn list_ops(State(s): State<Shared>, Query(q): Query<OpsQuery>) -> Json<OpsPage> {
    let limit = q.limit.unwrap_or(500).clamp(1, 1000);
    let ops: Vec<Op> = s
        .store
        .read(|l| l.ops_from(q.from, limit).into_iter().cloned().collect());
    let next = q.from + ops.len();
    Json(OpsPage { ops, next })
}

async fn get_op(State(s): State<Shared>, Path(id): Path<String>) -> Response {
    let Ok(id) = Hash::from_hex(&id) else {
        return error(StatusCode::BAD_REQUEST, "bad op id");
    };
    match s
        .store
        .read(|l| l.get(&id).cloned().map(|op| (op, l.status(&id).cloned())))
    {
        Some((op, status)) => Json(OpInfo { op, status }).into_response(),
        None => error(StatusCode::NOT_FOUND, "unknown operation"),
    }
}

async fn get_name(State(s): State<Shared>, Path(name): Path<String>) -> Response {
    let now = now_secs();
    let name = name.to_ascii_lowercase();
    match s.store.read(|l| l.record(&name).cloned()) {
        Some(record) => {
            let active = record.is_active(now);
            Json(NameInfo { record, active }).into_response()
        }
        None => error(StatusCode::NOT_FOUND, "name is not registered"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dweb_net::init();
    let args = Args::parse();
    let cfg = NetworkConfig::load(&args.config)?;
    let data_dir = args
        .data_dir
        .unwrap_or_else(|| dweb_net::default_data_dir("node").join(&cfg.network_name));
    let client = RegistryClient::new(&cfg.transport)?;
    let mut peers = cfg.bootstrap_nodes.clone();
    peers.extend(args.peers);

    let store = Arc::new(Store::open(cfg.clone(), Some(&data_dir))?);
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    let node_id = hex::encode(id);

    let syncer = Syncer::new(store.clone(), client.clone(), peers, Some(node_id.clone()));
    let state = Arc::new(AppState {
        store: store.clone(),
        node_id,
        network_name: cfg.network_name.clone(),
        client,
        peers: syncer.peers().to_vec(),
    });
    tokio::spawn(syncer.run(Duration::from_secs(args.sync_interval.max(1))));

    let app = Router::new()
        .route("/v1/info", get(info))
        .route("/v1/ops", get(list_ops).post(submit))
        .route("/v1/ops/{id}", get(get_op))
        .route("/v1/names/{name}", get(get_name))
        .with_state(state);

    tracing::info!(
        "network {} ({}), {} operations, data in {}",
        cfg.network_name,
        cfg.network_id(),
        store.read(|l| l.len()),
        data_dir.display()
    );
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!("registry API on http://{}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
