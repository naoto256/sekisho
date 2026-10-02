use thiserror::Error;

#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)] // ConfigurationError, ExternalServiceError are intentionally descriptive
pub enum Error {
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error("configuration error: {0}")]
    ConfigurationError(String),
    #[error("external service error: {0}")]
    ExternalServiceError(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("JWK with kid {0:?} not found in JWKS")]
    KidNotFound(Option<String>),
}

pub type Result<T> = std::result::Result<T, Error>;
