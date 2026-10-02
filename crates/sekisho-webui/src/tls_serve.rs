//! Optional rustls TLS termination for sekisho-webui.
//!
//! When the YAML carries a `tls:` block, sekisho-webui terminates
//! TLS itself instead of relying on a front proxy. The
//! implementation mirrors `kaido-webui::tls_serve` (custom accept
//! loop + hyper_util auto Builder) — keeping both in one shape
//! is intentional so an operator who's debugged one is at home
//! in the other.

use anyhow::{Context, Result, anyhow};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Build a rustls `ServerConfig` from PEM files on disk.
///
/// Files are read at startup once; rotating the cert at runtime
/// requires a SIGHUP-driven restart (sekisho-webui already restarts
/// cleanly via `Restart=on-failure` in the systemd unit).
pub fn load_server_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    let cert_bytes = std::fs::read(cert_path)
        .with_context(|| format!("read tls.cert: {}", cert_path.display()))?;
    let key_bytes =
        std::fs::read(key_path).with_context(|| format!("read tls.key: {}", key_path.display()))?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_bytes.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse tls.cert as PEM")?;
    if certs.is_empty() {
        return Err(anyhow!(
            "tls.cert contained no PEM CERTIFICATE blocks: {}",
            cert_path.display()
        ));
    }

    // `private_key` returns the first key found in any of PKCS#8,
    // RSA-PKCS#1, or SEC1 form — matching `rustls`' historical posture.
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_bytes.as_slice())
        .context("parse tls.key as PEM")?
        .ok_or_else(|| {
            anyhow!(
                "tls.key contained no PEM PRIVATE KEY blocks: {}",
                key_path.display()
            )
        })?;

    let cfg = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("select rustls protocol versions")?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("build rustls ServerConfig")?;
    Ok(Arc::new(cfg))
}

/// Serve `app` over TLS on `listener`. Runs until the listener
/// errors out — sekisho-webui has no graceful-shutdown signal in
/// the current shape, so this is symmetric with the historical
/// `axum::serve(listener, app).await?` plain-HTTP path.
pub async fn serve(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    app: axum::Router,
) -> Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let service = hyper_util::service::TowerToHyperService::new(app);
                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection_with_upgrades(io, service)
                    .await
                    {
                        tracing::debug!(peer = %peer, error = %e, "tls connection error");
                    }
                }
                Err(e) => {
                    tracing::debug!(peer = %peer, error = %e, "tls handshake failed");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_rejects_missing_cert_file() {
        let r = load_server_config(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
        );
        assert!(r.is_err());
    }

    #[test]
    fn load_rejects_empty_cert_pem() {
        let dir = std::env::temp_dir();
        let cert = dir.join(format!("sw-test-cert-{}.pem", std::process::id()));
        let key = dir.join(format!("sw-test-key-{}.pem", std::process::id()));
        std::fs::write(&cert, "not a pem").unwrap();
        std::fs::write(&key, "not a pem").unwrap();
        let r = load_server_config(&cert, &key);
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
        assert!(r.is_err());
    }
}
