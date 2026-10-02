//! Response-body resource ownership for proxied requests.
//!
//! Route concurrency permits and response idle timers must live until the
//! downstream finishes consuming the body, not merely until the handler
//! returns. This module owns that lifetime boundary.

use axum::body::Body;
use axum::http::Response;
use metrics::counter;
use tokio::sync::OwnedSemaphorePermit;

/// Resources acquired during a request that must survive past the handler.
///
/// Filled in as the request progresses (the route permit is only known once a
/// route matches) and applied by [`Self::wrap`] on the way out, on both the
/// success and error paths. Holding nothing is the common case for a 404, so
/// `wrap` returns the response untouched rather than paying for a body
/// wrapper that would do nothing.
pub(super) struct RouteResponseLease {
    pub(super) permit: Option<OwnedSemaphorePermit>,
    pub(super) idle_timeout: Option<std::time::Duration>,
    pub(super) route: Option<String>,
}

impl RouteResponseLease {
    pub(super) fn new() -> Self {
        Self {
            permit: None,
            idle_timeout: None,
            route: None,
        }
    }

    /// Attach the lease to the response body, or return the response as-is
    /// when there is nothing to hold.
    pub(super) fn wrap(&mut self, response: Response<Body>) -> Response<Body> {
        if self.permit.is_none() && self.idle_timeout.is_none() {
            return response;
        }
        let (parts, body) = response.into_parts();
        Response::from_parts(
            parts,
            Body::new(RouteLeaseBody::new(
                body,
                self.permit.take(),
                self.idle_timeout,
                self.route.clone().unwrap_or_else(|| "_unrouted".into()),
            )),
        )
    }
}

/// Response body that owns a concurrency permit and enforces the per-route
/// idle timeout.
///
/// The timer is reset on every non-empty DATA frame, so a slow-but-progressing
/// transfer is never cut off while a genuinely stalled upstream is. Empty
/// frames deliberately do not count as progress — trailers and zero-length
/// chunks would otherwise let an upstream keep the connection alive forever
/// without sending anything.
///
/// `done` latches so that a terminated stream cannot be polled back into
/// life: after the permit has been released, returning further frames would
/// mean serving a body outside the budget that authorized it.
struct RouteLeaseBody {
    inner: Body,
    permit: Option<OwnedSemaphorePermit>,
    idle: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    idle_timeout: Option<std::time::Duration>,
    route: String,
    done: bool,
}

impl RouteLeaseBody {
    fn new(
        inner: Body,
        permit: Option<OwnedSemaphorePermit>,
        idle_timeout: Option<std::time::Duration>,
        route: String,
    ) -> Self {
        Self {
            inner,
            permit,
            idle: idle_timeout.map(|timeout| Box::pin(tokio::time::sleep(timeout))),
            idle_timeout,
            route,
            done: false,
        }
    }

    /// Release the permit and drop the timer. Called on end-of-stream, on
    /// body error, and on idle expiry — every path out of the stream, so the
    /// permit cannot be stranded.
    fn finish(&mut self) {
        self.done = true;
        self.permit.take();
        self.idle.take();
    }
}

impl hyper::body::Body for RouteLeaseBody {
    type Data = axum::body::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.done {
            return std::task::Poll::Ready(None);
        }

        match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if frame.data_ref().is_some_and(|data| !data.is_empty())
                    && let (Some(idle), Some(timeout)) = (this.idle.as_mut(), this.idle_timeout)
                {
                    idle.as_mut().reset(tokio::time::Instant::now() + timeout);
                }
                return std::task::Poll::Ready(Some(Ok(frame)));
            }
            std::task::Poll::Ready(Some(Err(_))) => {
                this.finish();
                return std::task::Poll::Ready(Some(Err(std::io::Error::other(
                    "upstream response body error",
                ))));
            }
            std::task::Poll::Ready(None) => {
                this.finish();
                return std::task::Poll::Ready(None);
            }
            std::task::Poll::Pending => {}
        }

        if let Some(idle) = this.idle.as_mut()
            && idle.as_mut().poll(cx).is_ready()
        {
            tracing::warn!(
                route = %this.route,
                timeout_ms = this.idle_timeout.map(|v| v.as_millis() as u64).unwrap_or_default(),
                "upstream response body idle timeout"
            );
            counter!(
                "sekisho_proxy_response_body_idle_timeouts_total",
                "route" => this.route.clone()
            )
            .increment(1);
            this.finish();
            return std::task::Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upstream response body idle timeout",
            ))));
        }

        std::task::Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::sync::Arc;

    struct PendingBody;

    impl hyper::body::Body for PendingBody {
        type Data = axum::body::Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            std::task::Poll::Pending
        }
    }

    struct OneFrameBody(Option<Result<hyper::body::Frame<axum::body::Bytes>, std::io::Error>>);

    impl hyper::body::Body for OneFrameBody {
        type Data = axum::body::Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            std::task::Poll::Ready(self.0.take())
        }
    }

    fn leased_body(
        body: Body,
        semaphore: &Arc<tokio::sync::Semaphore>,
        idle: Option<std::time::Duration>,
    ) -> RouteLeaseBody {
        RouteLeaseBody::new(
            body,
            Some(semaphore.clone().try_acquire_owned().unwrap()),
            idle,
            "test-route".into(),
        )
    }

    #[tokio::test]
    async fn route_lease_releases_on_eof_error_drop_and_idle_expiry() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));

        let mut eof = leased_body(Body::empty(), &semaphore, None);
        assert!(eof.frame().await.is_none());
        assert_eq!(semaphore.available_permits(), 1);

        let mut error = leased_body(
            Body::new(OneFrameBody(Some(Err(std::io::Error::other(
                "fixture failure",
            ))))),
            &semaphore,
            None,
        );
        assert!(error.frame().await.expect("error frame").is_err());
        assert_eq!(semaphore.available_permits(), 1);

        let dropped = leased_body(Body::new(PendingBody), &semaphore, None);
        assert_eq!(semaphore.available_permits(), 0);
        drop(dropped);
        assert_eq!(semaphore.available_permits(), 1);

        let mut idle = leased_body(
            Body::new(PendingBody),
            &semaphore,
            Some(std::time::Duration::from_secs(60)),
        );
        idle.idle
            .as_mut()
            .expect("idle timer")
            .as_mut()
            .reset(tokio::time::Instant::now());
        let frame = idle.frame().await.expect("timeout frame");
        assert!(frame.is_err());
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn non_empty_data_resets_body_idle_deadline() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let mut body = leased_body(
            Body::new(OneFrameBody(Some(Ok(hyper::body::Frame::data(
                axum::body::Bytes::from_static(b"data"),
            ))))),
            &semaphore,
            Some(std::time::Duration::from_secs(60)),
        );
        body.idle
            .as_mut()
            .expect("idle timer")
            .as_mut()
            .reset(tokio::time::Instant::now());

        let frame = body
            .frame()
            .await
            .expect("data frame")
            .expect("successful data");
        assert_eq!(frame.data_ref().expect("DATA"), b"data".as_slice());
        assert!(body.idle.as_ref().expect("idle timer").deadline() > tokio::time::Instant::now());
        assert_eq!(semaphore.available_permits(), 0);
        assert!(body.frame().await.is_none());
        assert_eq!(semaphore.available_permits(), 1);
    }
}
