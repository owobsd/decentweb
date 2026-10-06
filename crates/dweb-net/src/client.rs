//! HTTP client for the registry API, used by nodes, resolvers and wallets.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use dweb_protocol::config::Transport;
use dweb_protocol::{Hash, Op};

use crate::api::{ErrorBody, Info, NameInfo, OpInfo, OpsPage, SubmitResponse};

#[derive(Clone)]
pub struct RegistryClient {
    http: reqwest::Client,
}

impl RegistryClient {
    /// Builds a client that routes through Tor or I2P if the transport says so.
    pub fn new(transport: &Transport) -> Result<Self> {
        let mut b = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(30))
            .user_agent(concat!("dweb/", env!("CARGO_PKG_VERSION")));
        if let Some(socks) = transport.socks_proxy() {
            // socks5h: the proxy resolves host names, so .onion works and
            // nothing leaks to local DNS.
            b = b.proxy(reqwest::Proxy::all(format!("socks5h://{socks}"))?);
        } else {
            b = b.no_proxy();
        }
        Ok(Self { http: b.build()? })
    }

    fn url(base: &str, path: &str) -> String {
        format!("{}{}", base.trim_end_matches('/'), path)
    }

    async fn read<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<Option<T>> {
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let text = resp.text().await?;
        if !status.is_success() {
            let msg = serde_json::from_str::<ErrorBody>(&text)
                .map(|e| e.error)
                .unwrap_or(text);
            bail!("registry returned {status}: {msg}");
        }
        Ok(Some(
            serde_json::from_str(&text).context("bad registry response")?,
        ))
    }

    pub async fn info(&self, base: &str) -> Result<Info> {
        let r = self.http.get(Self::url(base, "/v1/info")).send().await?;
        Self::read(r).await?.ok_or_else(|| anyhow!("no info"))
    }

    pub async fn submit(&self, base: &str, op: &Op) -> Result<SubmitResponse> {
        let r = self
            .http
            .post(Self::url(base, "/v1/ops"))
            .json(op)
            .send()
            .await?;
        Self::read(r).await?.ok_or_else(|| anyhow!("not found"))
    }

    pub async fn ops(&self, base: &str, from: usize, limit: usize) -> Result<OpsPage> {
        let r = self
            .http
            .get(Self::url(
                base,
                &format!("/v1/ops?from={from}&limit={limit}"),
            ))
            .send()
            .await?;
        Self::read(r).await?.ok_or_else(|| anyhow!("not found"))
    }

    pub async fn op(&self, base: &str, id: &Hash) -> Result<Option<OpInfo>> {
        let r = self
            .http
            .get(Self::url(base, &format!("/v1/ops/{id}")))
            .send()
            .await?;
        Self::read(r).await
    }

    pub async fn name(&self, base: &str, name: &str) -> Result<Option<NameInfo>> {
        let r = self
            .http
            .get(Self::url(base, &format!("/v1/names/{name}")))
            .send()
            .await?;
        Self::read(r).await
    }
}
