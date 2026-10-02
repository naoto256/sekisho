//! Per-listener source-IP ACL ("accept_from").
//!
//! Each network listener (proxy / management API / HTTP redirect) can
//! be paired with a comma-separated list of CIDRs or bare IPs. A bare
//! IP is interpreted as a host route (`/32` for IPv4, `/128` for
//! IPv6). When the list is empty the listener accepts any source —
//! the historical default.
//!
//! Why this lives here and not in routes/policies: this is a TCP-level
//! ingress filter, applied **before** TLS handshake / HTTP parsing.
//! Route-level ACLs are too late — they cost a TLS handshake per
//! probe and can't protect the management API from low-level scanning
//! traffic. Routes also operate on the *decoded* request, while this
//! module only sees the peer `SocketAddr`.
//!
//! Empty rule semantics: an explicit empty list means "any source",
//! not "deny all". Reasoning: the configured value is a string, the
//! default is `""`, and "default = lock everything out" would brick
//! every listener on first boot. Operators who want to deny all source
//! IPs should set the listen address to `127.0.0.1:<port>` instead.

use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AcceptFromError {
    #[error("invalid CIDR or IP '{entry}': {reason}; expected host or CIDR notation")]
    Invalid { entry: String, reason: String },
}

/// Parsed source-IP ACL.
///
/// `nets` empty ⇒ allow ANY. We deliberately encode "no rules
/// configured" rather than "explicit allow-list of zero entries" so
/// the empty-string config value round-trips with intuitive
/// semantics. There is no "allow none" state — the operator gets that
/// by binding to a different interface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceptFrom {
    nets: Vec<IpNet>,
}

impl AcceptFrom {
    /// Convenience for the "no filter" policy.
    pub fn any() -> Self {
        Self::default()
    }

    /// Parse a comma-separated list of CIDRs or bare IPs. Whitespace
    /// around entries is tolerated (operators copy/paste from docs).
    /// Empty / whitespace-only input ⇒ ANY policy.
    ///
    /// Bare IP entries are widened to host routes (`/32` / `/128`) so
    /// the rule list is uniformly an `IpNet`. Duplicates are de-duped
    /// to keep the canonical round-trip stable.
    pub fn parse(s: &str) -> Result<Self, AcceptFromError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(Self::any());
        }
        let mut nets: Vec<IpNet> = Vec::new();
        for raw in trimmed.split(',') {
            let entry = raw.trim();
            if entry.is_empty() {
                // Tolerate trailing comma / `a,,b`. Editor accidents
                // shouldn't hard-fail a config save.
                continue;
            }
            let net = parse_one(entry).map_err(|reason| AcceptFromError::Invalid {
                entry: entry.to_string(),
                reason,
            })?;
            if !nets.contains(&net) {
                nets.push(net);
            }
        }
        Ok(Self { nets })
    }

    /// True iff `ip` is allowed. Empty rule list returns `true`
    /// (default-allow); see the type-level doc for why.
    pub fn allows(&self, ip: IpAddr) -> bool {
        if self.nets.is_empty() {
            return true;
        }
        self.nets.iter().any(|n| n.contains(&ip))
    }

    /// Render back to the canonical comma-separated form. Order
    /// matches the input (modulo de-dup); we don't sort because
    /// operators sometimes use ordering to communicate intent (most
    /// specific first).
    pub fn to_string_canonical(&self) -> String {
        self.nets
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Whether the policy is the default ANY (no rules). Used at
    /// startup to log a one-line summary per listener so an operator
    /// can grep for "no source filter" surprises.
    pub fn is_any(&self) -> bool {
        self.nets.is_empty()
    }
}

/// Parse a single entry into an `IpNet`. Bare IPs widen to host
/// routes so the caller doesn't have to special-case them.
fn parse_one(entry: &str) -> Result<IpNet, String> {
    if entry.contains('/') {
        IpNet::from_str(entry).map_err(|e| e.to_string())
    } else {
        let ip = IpAddr::from_str(entry).map_err(|e| e.to_string())?;
        // `From<IpAddr> for IpNet` exists but goes through `/32` / `/128`
        // on the inner type — explicit `new` keeps the prefix length
        // visible.
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        IpNet::new(ip, prefix).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_input_is_any() {
        let acl = AcceptFrom::parse("").unwrap();
        assert!(acl.is_any());
        assert!(acl.allows(ip("8.8.8.8")));
        assert!(acl.allows(ip("::1")));
    }

    #[test]
    fn whitespace_only_is_any() {
        let acl = AcceptFrom::parse("   ").unwrap();
        assert!(acl.is_any());
    }

    #[test]
    fn bare_ipv4_matches_only_that_host() {
        let acl = AcceptFrom::parse("10.0.0.5").unwrap();
        assert!(acl.allows(ip("10.0.0.5")));
        assert!(!acl.allows(ip("10.0.0.6")));
        assert!(!acl.allows(ip("10.0.0.4")));
    }

    #[test]
    fn cidr_range_matches_inside_and_rejects_outside() {
        let acl = AcceptFrom::parse("172.17.0.0/24").unwrap();
        assert!(acl.allows(ip("172.17.0.1")));
        assert!(acl.allows(ip("172.17.0.255")));
        assert!(!acl.allows(ip("172.17.1.0")));
        assert!(!acl.allows(ip("10.0.0.1")));
    }

    #[test]
    fn ipv6_host_and_cidr() {
        let acl = AcceptFrom::parse("::1/128,fe80::/10").unwrap();
        assert!(acl.allows(ip("::1")));
        assert!(!acl.allows(ip("::2")));
        assert!(acl.allows(ip("fe80::1")));
        assert!(!acl.allows(ip("fc00::1")));
    }

    #[test]
    fn mixed_ipv4_ipv6_list() {
        let acl = AcceptFrom::parse("127.0.0.1/32, ::1/128, 10.0.0.0/8").unwrap();
        assert!(acl.allows(ip("127.0.0.1")));
        assert!(acl.allows(ip("::1")));
        assert!(acl.allows(ip("10.5.5.5")));
        assert!(!acl.allows(ip("8.8.8.8")));
    }

    #[test]
    fn invalid_entry_rejected_with_offending_value() {
        let err = AcceptFrom::parse("10.0.0.5,not-an-ip").unwrap_err();
        match err {
            AcceptFromError::Invalid { entry, .. } => assert_eq!(entry, "not-an-ip"),
        }
    }

    #[test]
    fn cidr_with_invalid_prefix_rejected() {
        assert!(AcceptFrom::parse("10.0.0.0/40").is_err());
    }

    #[test]
    fn duplicate_entries_are_deduped_in_canonical_form() {
        let acl = AcceptFrom::parse("10.0.0.0/8,10.0.0.0/8,127.0.0.1").unwrap();
        let canon = acl.to_string_canonical();
        // Both unique entries appear, no duplicate of 10.0.0.0/8.
        assert_eq!(canon.matches("10.0.0.0/8").count(), 1);
        assert!(canon.contains("127.0.0.1/32"));
    }

    #[test]
    fn trailing_and_inner_empty_segments_tolerated() {
        // Operators copy-paste from docs; an extra comma shouldn't
        // 400 the API.
        let acl = AcceptFrom::parse("10.0.0.1,,10.0.0.2,").unwrap();
        assert!(acl.allows(ip("10.0.0.1")));
        assert!(acl.allows(ip("10.0.0.2")));
        assert!(!acl.allows(ip("10.0.0.3")));
    }

    #[test]
    fn canonical_form_widens_bare_ips_to_host_routes() {
        // Round-trip stability: `10.0.0.5` becomes `10.0.0.5/32`
        // canonically. Lets the WebUI display the user's input in a
        // normalised form after save.
        let acl = AcceptFrom::parse("10.0.0.5").unwrap();
        assert_eq!(acl.to_string_canonical(), "10.0.0.5/32");
    }

    #[test]
    fn any_to_string_is_empty() {
        assert_eq!(AcceptFrom::any().to_string_canonical(), "");
    }

    #[test]
    fn allows_short_circuits_on_any() {
        // Empty list takes the fast path even for unusual addresses
        // — explicit smoke check on the hot-path branch.
        let any = AcceptFrom::any();
        assert!(any.allows(ip("0.0.0.0")));
        assert!(any.allows(ip("255.255.255.255")));
    }
}
