//! ACME Renewal Information (ARI) response boundary.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use instant_acme::{Account, CertificateIdentifier};
use rustls_pki_types::CertificateDer;
use time::OffsetDateTime;

use crate::{Error, RenewalInformationFailure, Result};

const MIN_RETRY_AFTER: Duration = Duration::from_secs(60);
const MAX_RETRY_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
const TEMPORARY_INITIAL_DELAY: Duration = Duration::from_secs(1);
const TEMPORARY_MAXIMUM_DELAY: Duration = Duration::from_secs(60);
const TEMPORARY_MAXIMUM_ATTEMPTS: u8 = 5;
const LONG_TERM_RETRY_AFTER: Duration = Duration::from_secs(6 * 60 * 60);

/// Capability-aware result of an ARI lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RenewalInformation {
    /// The directory supports ARI and returned validated advice.
    Supported(RenewalAdvice),
    /// The directory does not advertise ARI.
    Unsupported,
}

/// Validated renewal window and bounded refetch interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewalAdvice {
    /// Inclusive start of the CA's suggested renewal window.
    pub window_start: SystemTime,
    /// Exclusive end of the CA's suggested renewal window.
    pub window_end: SystemTime,
    /// Bounded interval after which the consumer should refresh advice.
    pub retry_after: Duration,
    /// Optional opaque explanatory URL supplied by the CA.
    pub explanation_url: Option<String>,
}

pub(crate) async fn renewal_info(
    account: &Account,
    certificate_der: &[u8],
) -> Result<RenewalInformation> {
    let certificate = CertificateDer::from(certificate_der);
    let identifier = CertificateIdentifier::try_from(&certificate)
        .map_err(|_| Error::InvalidPredecessorCertificate)?;
    let (information, retry_after) = match account.renewal_info(&identifier).await {
        Ok(value) => value,
        Err(instant_acme::Error::Unsupported(_)) => return Ok(RenewalInformation::Unsupported),
        Err(error) => return Err(map_ari_error(error)),
    };
    validated_advice(information, retry_after).map(RenewalInformation::Supported)
}

fn validated_advice(
    information: instant_acme::RenewalInfo,
    retry_after: Duration,
) -> Result<RenewalAdvice> {
    let window_start = system_time(information.suggested_window.start)?;
    let window_end = system_time(information.suggested_window.end)?;
    if window_end <= window_start {
        return Err(long_term_failure());
    }
    Ok(RenewalAdvice {
        window_start,
        window_end,
        retry_after: retry_after.clamp(MIN_RETRY_AFTER, MAX_RETRY_AFTER),
        explanation_url: information.explanation_url,
    })
}

fn map_ari_error(error: instant_acme::Error) -> Error {
    match error {
        instant_acme::Error::Unsupported(_) => Error::Unsupported("ACME renewal information"),
        instant_acme::Error::Timeout(_) => temporary_failure(),
        instant_acme::Error::Hyper(error) if error.is_timeout() => temporary_failure(),
        instant_acme::Error::Api(problem)
            if problem
                .status
                .is_some_and(|status| status == 408 || (500..600).contains(&status)) =>
        {
            temporary_failure()
        }
        instant_acme::Error::Other(error) if error_chain_timed_out(error.as_ref()) => {
            temporary_failure()
        }
        _ => long_term_failure(),
    }
}

fn temporary_failure() -> Error {
    RenewalInformationFailure::Temporary {
        initial_delay: TEMPORARY_INITIAL_DELAY,
        maximum_delay: TEMPORARY_MAXIMUM_DELAY,
        maximum_attempts: TEMPORARY_MAXIMUM_ATTEMPTS,
        exhausted_retry_after: LONG_TERM_RETRY_AFTER,
    }
    .into()
}

fn long_term_failure() -> Error {
    RenewalInformationFailure::LongTerm {
        retry_after: LONG_TERM_RETRY_AFTER,
    }
    .into()
}

fn error_chain_timed_out(mut error: &(dyn std::error::Error + 'static)) -> bool {
    loop {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
        {
            return true;
        }
        let Some(source) = error.source() else {
            return false;
        };
        error = source;
    }
}

fn system_time(value: OffsetDateTime) -> Result<SystemTime> {
    let seconds = value.unix_timestamp();
    let nanos = value.nanosecond();
    if seconds >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::new(seconds.unsigned_abs(), nanos))
            .ok_or_else(long_term_failure)
    } else {
        let before = Duration::new(seconds.unsigned_abs(), 0);
        UNIX_EPOCH
            .checked_sub(before)
            .and_then(|value| value.checked_add(Duration::from_nanos(u64::from(nanos))))
            .ok_or_else(long_term_failure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_is_clamped_to_safe_bounds() {
        assert_eq!(
            Duration::ZERO.clamp(MIN_RETRY_AFTER, MAX_RETRY_AFTER),
            MIN_RETRY_AFTER
        );
        assert_eq!(
            Duration::from_secs(48 * 60 * 60).clamp(MIN_RETRY_AFTER, MAX_RETRY_AFTER),
            MAX_RETRY_AFTER
        );
    }

    #[test]
    fn pre_epoch_time_conversion_is_exact() {
        let value = OffsetDateTime::from_unix_timestamp_nanos(-500_000_000).unwrap();
        assert_eq!(
            system_time(value).unwrap(),
            UNIX_EPOCH - Duration::from_millis(500)
        );
    }

    #[test]
    fn reversed_window_is_retryable_invalid_information() {
        let information = instant_acme::RenewalInfo {
            suggested_window: instant_acme::SuggestedWindow {
                start: OffsetDateTime::from_unix_timestamp(20).unwrap(),
                end: OffsetDateTime::from_unix_timestamp(10).unwrap(),
            },
            explanation_url: None,
        };
        let error = validated_advice(information, Duration::from_secs(300)).unwrap_err();
        assert!(matches!(
            error,
            Error::RenewalInformation(RenewalInformationFailure::LongTerm {
                retry_after: LONG_TERM_RETRY_AFTER
            })
        ));
        assert!(error.is_retryable());
    }

    #[test]
    fn timeout_and_server_error_are_temporary() {
        for error in [
            instant_acme::Error::Timeout(None),
            instant_acme::Error::Other(Box::new(std::io::Error::from(
                std::io::ErrorKind::TimedOut,
            ))),
            instant_acme::Error::Api(instant_acme::Problem {
                r#type: None,
                detail: None,
                status: Some(408),
                subproblems: Vec::new(),
            }),
            instant_acme::Error::Api(instant_acme::Problem {
                r#type: None,
                detail: None,
                status: Some(503),
                subproblems: Vec::new(),
            }),
        ] {
            assert!(matches!(
                map_ari_error(error),
                Error::RenewalInformation(RenewalInformationFailure::Temporary {
                    initial_delay: TEMPORARY_INITIAL_DELAY,
                    maximum_delay: TEMPORARY_MAXIMUM_DELAY,
                    maximum_attempts: TEMPORARY_MAXIMUM_ATTEMPTS,
                    exhausted_retry_after: LONG_TERM_RETRY_AFTER,
                })
            ));
        }
    }

    #[test]
    fn refused_and_non_server_errors_are_long_term() {
        for error in [
            instant_acme::Error::Other(Box::new(std::io::Error::from(
                std::io::ErrorKind::ConnectionRefused,
            ))),
            instant_acme::Error::Api(instant_acme::Problem {
                r#type: None,
                detail: None,
                status: Some(429),
                subproblems: Vec::new(),
            }),
            instant_acme::Error::Str("missing Retry-After header"),
        ] {
            assert!(matches!(
                map_ari_error(error),
                Error::RenewalInformation(RenewalInformationFailure::LongTerm {
                    retry_after: LONG_TERM_RETRY_AFTER
                })
            ));
        }
    }
}
