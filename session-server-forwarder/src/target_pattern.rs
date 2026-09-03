//! Patterns that select [`SessionTarget`]s, used to attach admission rules to classes of target.
//!
//! The grammar is a single string so that a rule reads as one line of configuration, matching how
//! [`target_allow_list`](crate::config::SessionIpForwardingConfig::target_allow_list) already spells
//! its addresses:
//!
//! | Pattern | Matches |
//! |---|---|
//! | `*` | every target, including services |
//! | `tcp:example.com:443` | that name, over TCP, on that port |
//! | `tcp:*:443` | any host, over TCP, on port 443 |
//! | `tcp:*.example.com:*` | any subdomain of `example.com`, over TCP, on any port |
//! | `udp:10.0.0.0/8:*` | any address in that block, over UDP |
//! | `*:*:53` | port 53, over either protocol |
//! | `service:0` | the node-local service with that id |
//! | `service:*` | any node-local service |
//!
//! Matching runs against the *unsealed* target, so a rule is written in terms of the host the peer
//! actually asked for rather than the ciphertext it travelled as.

use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
    str::FromStr,
};

use hopr_utils::network_types::prelude::{IpOrHost, IpProtocol, ServiceId, SessionTarget};

/// Error produced when a [`TargetPattern`] cannot be parsed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid target pattern '{pattern}': {reason}")]
pub struct InvalidTargetPattern {
    /// The pattern as written.
    pub pattern: String,
    /// Why it was rejected.
    pub reason: String,
}

impl InvalidTargetPattern {
    fn new(pattern: &str, reason: impl Display) -> Self {
        Self {
            pattern: pattern.to_string(),
            reason: reason.to_string(),
        }
    }
}

/// Which transport a stream pattern selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolPattern {
    /// Either transport.
    Any,
    /// That transport only.
    Only(IpProtocol),
}

/// Which host a stream pattern selects.
///
/// A name pattern never matches an address and an address pattern never matches a name: the two are
/// different things to the operator, and silently equating them would let `10.0.0.0/8` also capture
/// a target that merely resolves into that block later, which is the allow-list's job and is checked
/// after resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// Any host.
    Any,
    /// One exact DNS name, compared case-insensitively.
    Name(String),
    /// Any strict subdomain of this name — `*.example.com` does not match `example.com` itself.
    Subdomain(String),
    /// One exact IP address.
    Address(IpAddr),
    /// Any address inside this block.
    Network(ipnet::IpNet),
}

/// Which port a stream pattern selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortPattern {
    /// Any port.
    Any,
    /// One exact port.
    Exact(u16),
}

/// Selects a class of [`SessionTarget`]. See the [module documentation](self) for the grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetPattern {
    /// Matches every target.
    Any,
    /// Matches node-local services, either one by id or all of them.
    Service(Option<ServiceId>),
    /// Matches forwarded TCP/UDP streams.
    Stream {
        /// The transport to match.
        protocol: ProtocolPattern,
        /// The host to match.
        host: HostPattern,
        /// The port to match.
        port: PortPattern,
    },
}

impl TargetPattern {
    /// Whether this pattern selects `target`, whose host must already be unsealed.
    pub fn matches(&self, target: &UnsealedTarget) -> bool {
        match (self, target) {
            (TargetPattern::Any, _) => true,
            (TargetPattern::Service(None), UnsealedTarget::Service(_)) => true,
            (TargetPattern::Service(Some(wanted)), UnsealedTarget::Service(id)) => wanted == id,
            (TargetPattern::Service(_), _) | (TargetPattern::Stream { .. }, UnsealedTarget::Service(_)) => false,
            (
                TargetPattern::Stream { protocol, host, port },
                UnsealedTarget::Stream {
                    protocol: target_protocol,
                    host: target_host,
                },
            ) => protocol.matches(*target_protocol) && port.matches(target_host.port()) && host.matches(target_host),
        }
    }
}

impl ProtocolPattern {
    fn matches(self, protocol: IpProtocol) -> bool {
        match self {
            ProtocolPattern::Any => true,
            ProtocolPattern::Only(wanted) => wanted == protocol,
        }
    }
}

impl PortPattern {
    fn matches(self, port: u16) -> bool {
        match self {
            PortPattern::Any => true,
            PortPattern::Exact(wanted) => wanted == port,
        }
    }
}

impl HostPattern {
    fn matches(&self, host: &IpOrHost) -> bool {
        match (self, host) {
            (HostPattern::Any, _) => true,
            (HostPattern::Name(wanted), IpOrHost::Dns(name, _)) => wanted.eq_ignore_ascii_case(without_root_dot(name)),
            (HostPattern::Subdomain(suffix), IpOrHost::Dns(name, _)) => {
                let name = without_root_dot(name);
                name.len()
                    .checked_sub(suffix.len())
                    .and_then(|split| split.checked_sub(1))
                    .is_some_and(|dot| name.as_bytes()[dot] == b'.' && suffix.eq_ignore_ascii_case(&name[dot + 1..]))
            }
            (HostPattern::Address(wanted), IpOrHost::Ip(addr)) => *wanted == addr.ip(),
            (HostPattern::Network(net), IpOrHost::Ip(addr)) => net.contains(&addr.ip()),
            // A name pattern against an address, or an address pattern against a name.
            (HostPattern::Name(_) | HostPattern::Subdomain(_), IpOrHost::Ip(_))
            | (HostPattern::Address(_) | HostPattern::Network(_), IpOrHost::Dns(..)) => false,
        }
    }
}

/// Drops one trailing DNS root dot.
///
/// `example.com.` and `example.com` name the same host and resolve alike, so a rule has to price
/// them alike. Comparing them literally would let a peer pick the spelling the rule does not match,
/// fall through to the node's default terms, and reach the very same target — and the peer chooses
/// the spelling, so the bypass would be theirs to take.
fn without_root_dot(name: &str) -> &str {
    name.strip_suffix('.').unwrap_or(name)
}

/// Puts a name written in a pattern into the form [`HostPattern`] compares against, rejecting what
/// no DNS name can equal.
///
/// The rejection matters more than it looks. A host that reaches here is otherwise taken as a
/// literal name, so `*example.com` (a missing dot) or `ex ample.com` (a stray space) parses happily
/// and then matches nothing — and a rule that matches nothing is not inert, it drops its whole class
/// back to the node's default terms. For a rule written to *demand* payment that fails open, and
/// silently. The parser already rejects a bad port and a bad CIDR block loudly; a name that cannot
/// be a name deserves the same.
fn dns_name(pattern: &str, name: &str) -> Result<String, InvalidTargetPattern> {
    let name = without_root_dot(name);

    if name.is_empty() {
        return Err(InvalidTargetPattern::new(pattern, "empty host name"));
    }

    // Punycode has already folded internationalized names into this set by the time anyone writes
    // one down, and `_` is here for the underscore labels that service records use.
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
    {
        return Err(InvalidTargetPattern::new(
            pattern,
            format!("'{name}' is not a DNS name; a wildcard label is written '*.'"),
        ));
    }

    Ok(name.to_ascii_lowercase())
}

/// A [`SessionTarget`] with its host opened, which is the form rules are matched against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsealedTarget {
    /// A forwarded TCP or UDP stream.
    Stream {
        /// The transport it is forwarded over.
        protocol: IpProtocol,
        /// The host it is forwarded to, unsealed.
        host: IpOrHost,
    },
    /// A node-local service.
    Service(ServiceId),
}

impl UnsealedTarget {
    /// Opens `target`'s host with `keypair`, so it can be matched against a [`TargetPattern`].
    ///
    /// A [`SessionTarget::ExitNode`] carries no host and cannot be sealed, so it needs no key.
    pub fn new(
        target: &SessionTarget,
        keypair: &hopr_api::types::crypto::prelude::OffchainKeypair,
    ) -> Result<Self, hopr_utils::network_types::errors::NetworkTypeError> {
        let (protocol, sealed) = match target {
            SessionTarget::TcpStream(host) => (IpProtocol::TCP, host),
            SessionTarget::UdpStream(host) => (IpProtocol::UDP, host),
            SessionTarget::ExitNode(id) => return Ok(UnsealedTarget::Service(*id)),
        };

        Ok(UnsealedTarget::Stream {
            protocol,
            host: sealed.clone().unseal(keypair)?,
        })
    }
}

impl FromStr for TargetPattern {
    type Err = InvalidTargetPattern;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pattern = s.trim();
        if pattern == "*" {
            return Ok(TargetPattern::Any);
        }

        // The protocol is up to the first colon and the port after the last, which leaves everything
        // between them as the host. Splitting that way rather than on every colon is what lets an
        // IPv6 literal or a CIDR block sit in the middle unquoted.
        let (protocol, rest) = pattern
            .split_once(':')
            .ok_or_else(|| InvalidTargetPattern::new(pattern, "expected '<protocol>:<host>:<port>' or '*'"))?;

        if protocol.eq_ignore_ascii_case("service") {
            return match rest {
                "*" => Ok(TargetPattern::Service(None)),
                id => id
                    .parse()
                    .map(|id| TargetPattern::Service(Some(id)))
                    .map_err(|e| InvalidTargetPattern::new(pattern, format!("service id: {e}"))),
            };
        }

        let protocol = match protocol {
            "*" => ProtocolPattern::Any,
            // `IpProtocol`'s own parser is case-insensitive, so `TCP` and `tcp` are one pattern.
            other => ProtocolPattern::Only(other.parse().map_err(|_| {
                InvalidTargetPattern::new(
                    pattern,
                    format!("unknown protocol '{other}', expected 'tcp', 'udp', 'service' or '*'"),
                )
            })?),
        };

        let (host, port) = rest
            .rsplit_once(':')
            .ok_or_else(|| InvalidTargetPattern::new(pattern, "missing ':<port>'"))?;

        let port = match port {
            "*" => PortPattern::Any,
            number => PortPattern::Exact(
                number
                    .parse()
                    .map_err(|e| InvalidTargetPattern::new(pattern, format!("port: {e}")))?,
            ),
        };

        let host = if host == "*" {
            HostPattern::Any
        } else if let Some(suffix) = host.strip_prefix("*.") {
            HostPattern::Subdomain(dns_name(pattern, suffix)?)
        } else if host.contains('/') {
            HostPattern::Network(
                host.parse()
                    .map_err(|e| InvalidTargetPattern::new(pattern, format!("network: {e}")))?,
            )
        } else if let Some(literal) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            // Bracketed IPv6, the form a `host:port` string has to use to be unambiguous.
            HostPattern::Address(
                literal
                    .parse()
                    .map_err(|e| InvalidTargetPattern::new(pattern, format!("address: {e}")))?,
            )
        } else if let Ok(address) = host.parse() {
            HostPattern::Address(address)
        } else {
            HostPattern::Name(dns_name(pattern, host)?)
        };

        Ok(TargetPattern::Stream { protocol, host, port })
    }
}

impl Display for TargetPattern {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetPattern::Any => write!(f, "*"),
            TargetPattern::Service(None) => write!(f, "service:*"),
            TargetPattern::Service(Some(id)) => write!(f, "service:{id}"),
            TargetPattern::Stream { protocol, host, port } => {
                match protocol {
                    ProtocolPattern::Any => write!(f, "*:")?,
                    // `IpProtocol` renders lowercase, which is the form the parser reads back.
                    ProtocolPattern::Only(protocol) => write!(f, "{protocol}:")?,
                }
                match host {
                    HostPattern::Any => write!(f, "*")?,
                    HostPattern::Name(name) => write!(f, "{name}")?,
                    HostPattern::Subdomain(suffix) => write!(f, "*.{suffix}")?,
                    HostPattern::Address(addr @ IpAddr::V6(_)) => write!(f, "[{addr}]")?,
                    HostPattern::Address(addr) => write!(f, "{addr}")?,
                    HostPattern::Network(net) => write!(f, "{net}")?,
                }
                match port {
                    PortPattern::Any => write!(f, ":*"),
                    PortPattern::Exact(port) => write!(f, ":{port}"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;

    use super::*;

    fn dns(name: &str, port: u16) -> UnsealedTarget {
        UnsealedTarget::Stream {
            protocol: IpProtocol::TCP,
            host: IpOrHost::Dns(name.into(), port),
        }
    }

    fn ip(addr: &str, protocol: IpProtocol) -> anyhow::Result<UnsealedTarget> {
        Ok(UnsealedTarget::Stream {
            protocol,
            host: IpOrHost::Ip(addr.parse().context("parsing socket address")?),
        })
    }

    fn parse(pattern: &str) -> anyhow::Result<TargetPattern> {
        pattern.parse().context("parsing target pattern")
    }

    #[test]
    fn every_pattern_survives_a_string_round_trip() -> anyhow::Result<()> {
        for pattern in [
            "*",
            "service:*",
            "service:7",
            "tcp:example.com:443",
            "udp:*:53",
            "*:*:*",
            "tcp:*.example.com:*",
            "udp:10.0.0.0/8:*",
            "tcp:192.168.1.1:8080",
            "tcp:[2001:db8::1]:443",
            "udp:2001:db8::/32:*",
        ] {
            assert_eq!(parse(pattern)?.to_string(), pattern, "round trip of {pattern}");
        }
        Ok(())
    }

    #[test]
    fn the_catch_all_matches_streams_and_services_alike() -> anyhow::Result<()> {
        let any = parse("*")?;
        assert!(any.matches(&dns("example.com", 443)));
        assert!(any.matches(&ip("10.1.2.3:80", IpProtocol::UDP)?));
        assert!(any.matches(&UnsealedTarget::Service(0)));
        Ok(())
    }

    #[test]
    fn a_service_pattern_matches_only_services() -> anyhow::Result<()> {
        assert!(parse("service:0")?.matches(&UnsealedTarget::Service(0)));
        assert!(!parse("service:0")?.matches(&UnsealedTarget::Service(1)));
        assert!(!parse("service:0")?.matches(&dns("example.com", 443)));

        assert!(parse("service:*")?.matches(&UnsealedTarget::Service(9)));
        // …and a stream pattern never captures a service, however wild.
        assert!(!parse("*:*:*")?.matches(&UnsealedTarget::Service(0)));
        Ok(())
    }

    #[test]
    fn protocol_and_port_narrow_independently() -> anyhow::Result<()> {
        let tcp_443 = parse("tcp:*:443")?;
        assert!(tcp_443.matches(&dns("example.com", 443)));
        assert!(!tcp_443.matches(&dns("example.com", 80)));
        assert!(!tcp_443.matches(&UnsealedTarget::Stream {
            protocol: IpProtocol::UDP,
            host: IpOrHost::Dns("example.com".into(), 443),
        }));

        let any_proto_53 = parse("*:*:53")?;
        assert!(any_proto_53.matches(&ip("1.1.1.1:53", IpProtocol::UDP)?));
        assert!(any_proto_53.matches(&ip("1.1.1.1:53", IpProtocol::TCP)?));
        Ok(())
    }

    /// The protocol is spelled however the operator spelled it, and normalizes on the way back out.
    #[test]
    fn the_protocol_is_read_case_insensitively() -> anyhow::Result<()> {
        assert_eq!(parse("TCP:example.com:443")?, parse("tcp:example.com:443")?);
        assert_eq!(parse("Udp:*:53")?.to_string(), "udp:*:53");
        Ok(())
    }

    #[test]
    fn a_subdomain_pattern_excludes_the_bare_name_and_sibling_names() -> anyhow::Result<()> {
        let pattern = parse("tcp:*.example.com:*")?;

        assert!(pattern.matches(&dns("a.example.com", 443)));
        assert!(pattern.matches(&dns("deep.nested.example.com", 1)));
        // Case is irrelevant in DNS.
        assert!(pattern.matches(&dns("A.Example.COM", 443)));

        // The bare name is not a subdomain of itself.
        assert!(!pattern.matches(&dns("example.com", 443)));
        // Nor is a name that merely ends with the same characters.
        assert!(!pattern.matches(&dns("notexample.com", 443)));
        assert!(!pattern.matches(&dns("evil-example.com", 443)));
        Ok(())
    }

    /// The peer chooses how it spells the name, so the two spellings of one host must price alike —
    /// otherwise the fully qualified form is a way to miss the rule and get the node's default terms.
    #[test]
    fn a_fully_qualified_name_is_the_same_host_as_the_bare_one() -> anyhow::Result<()> {
        let exact = parse("tcp:example.com:443")?;
        assert!(exact.matches(&dns("example.com.", 443)), "peer wrote the root dot");
        assert!(
            parse("tcp:example.com.:443")?.matches(&dns("example.com", 443)),
            "operator wrote the root dot"
        );
        assert_eq!(parse("tcp:example.com.:443")?, exact, "and they are one pattern");

        let subdomain = parse("tcp:*.example.com:*")?;
        assert!(subdomain.matches(&dns("a.example.com.", 443)));
        assert!(parse("tcp:*.example.com.:*")?.matches(&dns("a.example.com", 443)));
        // The exclusions survive normalization: the bare name is still not its own subdomain.
        assert!(!subdomain.matches(&dns("example.com.", 443)));
        assert!(!subdomain.matches(&dns("notexample.com.", 443)));
        Ok(())
    }

    #[test]
    fn names_and_addresses_never_match_each_others_patterns() -> anyhow::Result<()> {
        assert!(!parse("tcp:*.example.com:*")?.matches(&ip("10.0.0.1:443", IpProtocol::TCP)?));
        assert!(!parse("tcp:example.com:443")?.matches(&ip("10.0.0.1:443", IpProtocol::TCP)?));
        assert!(!parse("tcp:10.0.0.0/8:*")?.matches(&dns("example.com", 443)));
        assert!(!parse("tcp:10.0.0.1:443")?.matches(&dns("10.0.0.1", 443)));
        Ok(())
    }

    #[test]
    fn a_network_pattern_matches_inside_the_block_only() -> anyhow::Result<()> {
        let private = parse("udp:10.0.0.0/8:*")?;
        assert!(private.matches(&ip("10.1.2.3:53", IpProtocol::UDP)?));
        assert!(private.matches(&ip("10.255.255.255:1", IpProtocol::UDP)?));
        assert!(!private.matches(&ip("11.0.0.1:53", IpProtocol::UDP)?));

        let v6 = parse("tcp:2001:db8::/32:*")?;
        assert!(v6.matches(&ip("[2001:db8::1]:443", IpProtocol::TCP)?));
        assert!(!v6.matches(&ip("[2001:db9::1]:443", IpProtocol::TCP)?));
        Ok(())
    }

    #[test]
    fn a_bracketed_v6_literal_matches_that_address_alone() -> anyhow::Result<()> {
        let pattern = parse("tcp:[2001:db8::1]:443")?;
        assert!(pattern.matches(&ip("[2001:db8::1]:443", IpProtocol::TCP)?));
        assert!(!pattern.matches(&ip("[2001:db8::2]:443", IpProtocol::TCP)?));
        Ok(())
    }

    #[test]
    fn malformed_patterns_are_rejected_rather_than_silently_narrowed() {
        for pattern in [
            "",
            "tcp",
            "tcp:example.com",
            "sctp:*:443",
            "tcp:*:notaport",
            "tcp:*:70000",
            "tcp:*.:443",
            "tcp::443",
            "service:nine",
            "tcp:10.0.0.0/99:*",
            // A name no `IpOrHost::Dns` can equal matches nothing, and a rule that matches nothing
            // hands its class back to the node's default terms — the permissive direction, so these
            // have to fail at load rather than at midnight.
            "tcp:*example.com:443",
            "tcp:ex ample.com:443",
            "tcp:exam!ple.com:443",
            // Neither a bracketed literal, a parsable address, nor a network: the colon is what the
            // two-ended split leaves behind, not a host anyone meant to write.
            "tcp:a:b:c:443",
            // A bare root dot names nothing once normalized.
            "tcp:.:443",
            "tcp:*..:443",
        ] {
            assert!(
                pattern.parse::<TargetPattern>().is_err(),
                "'{pattern}' should not parse"
            );
        }
    }
}
