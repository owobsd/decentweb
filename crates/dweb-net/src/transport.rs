//! Opens TCP connections to site servers, directly or through a SOCKS5
//! proxy (Tor or I2P).

use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Connects to `addr` (`ip:port`, `[v6]:port`, `x.onion:port`, `x.i2p:port`).
pub async fn connect(addr: &str, socks: Option<&str>) -> Result<TcpStream> {
    let fut = async {
        match socks {
            Some(proxy) => socks5_connect(proxy, addr).await,
            None => {
                if addr.contains(".onion:") || addr.contains(".i2p:") {
                    bail!("{addr} needs Tor or I2P; set [transport] mode in network.toml");
                }
                Ok(TcpStream::connect(addr).await?)
            }
        }
    };
    tokio::time::timeout(CONNECT_TIMEOUT, fut)
        .await
        .with_context(|| format!("timed out connecting to {addr}"))?
}

/// Minimal SOCKS5 CONNECT (RFC 1928) without authentication. The target host
/// is sent as a domain name so the proxy resolves it.
async fn socks5_connect(proxy: &str, addr: &str) -> Result<TcpStream> {
    let (host, port) = addr.rsplit_once(':').context("address has no port")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().context("bad port")?;
    if host.len() > 255 {
        bail!("host too long");
    }
    let mut s = TcpStream::connect(proxy)
        .await
        .with_context(|| format!("cannot reach SOCKS proxy {proxy} (is Tor/I2P running?)"))?;
    s.write_all(&[5, 1, 0]).await?;
    let mut buf = [0u8; 2];
    s.read_exact(&mut buf).await?;
    if buf != [5, 0] {
        bail!("SOCKS proxy refused no-auth method");
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0 {
        bail!("SOCKS proxy could not connect to {addr} (code {})", head[1]);
    }
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        _ => bail!("bad SOCKS reply"),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest).await?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A fake SOCKS5 proxy that checks the request and echoes one message.
    #[tokio::test]
    async fn socks5_sends_onion_host_to_proxy() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = l.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut hello = [0u8; 3];
            s.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello, [5, 1, 0]);
            s.write_all(&[5, 0]).await.unwrap();
            let mut head = [0u8; 5];
            s.read_exact(&mut head).await.unwrap();
            assert_eq!(&head[..4], &[5, 1, 0, 3]);
            let mut host = vec![0u8; head[4] as usize];
            s.read_exact(&mut host).await.unwrap();
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();
            assert_eq!(host, b"abcdef.onion");
            assert_eq!(u16::from_be_bytes(port), 443);
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            s.write_all(b"tunnel").await.unwrap();
        });
        let mut s = connect("abcdef.onion:443", Some(&proxy)).await.unwrap();
        let mut buf = [0u8; 6];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"tunnel");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn onion_without_proxy_is_refused() {
        assert!(connect("abcdef.onion:443", None).await.is_err());
    }
}
