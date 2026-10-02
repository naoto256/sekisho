//! Shared HTTP helpers for fetching IdP metadata / discovery / JWKS.

/// Read a reqwest response with a maximum size limit (bytes).
///
/// Streams the body chunk-by-chunk and aborts as soon as the cumulative size
/// exceeds `max_bytes`. A declared `Content-Length` over the limit short-circuits
/// before any body is read. A missing or under-declared `Content-Length` (including
/// chunked encoding) cannot bypass the check — an upstream that streams beyond the
/// limit is rejected mid-read without further buffering.
pub async fn limited_response(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length()
        && len as usize > max_bytes
    {
        return Err(format!("response too large: {len} bytes (max {max_bytes})"));
    }
    let mut buf: Vec<u8> = Vec::with_capacity(usize::min(max_bytes, 64 * 1024));
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Err(format!(
                "response too large: exceeded {max_bytes} bytes while reading"
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawn a one-shot TCP server that swallows a single request and writes `response` verbatim.
    async fn spawn_raw_server(response: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(&response).await;
                let _ = sock.shutdown().await;
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn limited_response_passes_small_body() {
        let body = b"hello";
        let mut raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(body);
        let url = spawn_raw_server(raw).await;
        let resp = reqwest::get(&url).await.unwrap();
        let out = limited_response(resp, 1024).await.unwrap();
        assert_eq!(out, b"hello");
    }

    #[tokio::test]
    async fn limited_response_rejects_oversize_content_length_before_reading() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\nConnection: close\r\n\r\n".to_vec();
        let url = spawn_raw_server(raw).await;
        let resp = reqwest::get(&url).await.unwrap();
        let err = limited_response(resp, 1024).await.unwrap_err();
        assert!(err.contains("too large"), "unexpected: {err}");
    }

    #[tokio::test]
    async fn limited_response_rejects_chunked_overflow_mid_stream() {
        // Chunked encoding, no Content-Length: streams 4 KiB but limit is 2 KiB.
        let mut raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
        for _ in 0..4 {
            raw.extend_from_slice(b"400\r\n");
            raw.extend_from_slice(&[b'A'; 0x400]);
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"0\r\n\r\n");
        let url = spawn_raw_server(raw).await;
        let resp = reqwest::get(&url).await.unwrap();
        let err = limited_response(resp, 2048).await.unwrap_err();
        assert!(err.contains("too large"), "unexpected: {err}");
    }
}
