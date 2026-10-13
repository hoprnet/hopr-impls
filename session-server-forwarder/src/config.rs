use std::{collections::HashSet, net::SocketAddr, num::NonZeroUsize, time::Duration};

use hopr_utils::network_types::prelude::IpOrHost;
use serde_with::serde_as;
// In scope for the `#[validate(nested)]` on `session_admission_rules`, whose generated code calls
// `Validate::validate` on the `Vec`.
use validator::Validate;

use crate::target_pattern::{TargetPattern, is_dns_charset, without_root_dot};

/// Configuration of the Exit node (see [`HoprServerIpForwardingReactor`](crate::HoprServerIpForwardingReactor))
/// and the Entry node.
#[serde_as]
#[derive(
    Clone, Debug, Eq, PartialEq, smart_default::SmartDefault, serde::Deserialize, serde::Serialize, validator::Validate,
)]
pub struct SessionIpForwardingConfig {
    /// Controls whether allowlisting should be done via `target_allow_list`.
    /// If set to `false`, the node will act as an Exit node for any target.
    ///
    /// Defaults to `true`.
    #[serde(default = "just_true")]
    #[default(true)]
    pub use_target_allow_list: bool,

    /// Enforces only the given targets, each an `IP:PORT` or a `NAME:PORT`.
    ///
    /// A target is allowed if it is a listed name on its port, or if the addresses it resolves to are
    /// listed, either literally or as what a listed name resolves to at that moment. Names are
    /// resolved for every Session rather than once at startup, subject to the resolver's own caching.
    /// List only names you control, since whoever controls a name decides where it leads.
    ///
    /// This is used only if `use_target_allow_list` is set to `true`.
    /// If left empty (and `use_target_allow_list` is `true`), the node will not act as an Exit node.
    ///
    /// Defaults to empty.
    #[serde(default)]
    #[serde_as(as = "HashSet<serde_with::DisplayFromStr>")]
    #[validate(custom(function = "validate_target_allow_list"))]
    pub target_allow_list: HashSet<IpOrHost>,

    /// Delay between retries in seconds to reach a TCP target.
    ///
    /// Defaults to 2 seconds.
    #[serde(default = "default_target_retry_delay")]
    #[default(default_target_retry_delay())]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    pub tcp_target_retry_delay: Duration,

    /// Maximum number of retries to reach a TCP target before giving up.
    ///
    /// Default is 10.
    #[serde(default = "default_max_tcp_target_retries")]
    #[default(default_max_tcp_target_retries())]
    #[validate(range(min = 1))]
    pub max_tcp_target_retries: u32,

    /// Specifies the default `listen_host` for Session listening sockets
    /// at an Entry node.
    #[serde(default = "default_entry_listen_host")]
    #[default(default_entry_listen_host())]
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub default_entry_listen_host: SocketAddr,

    /// Number of parallel UDP receiver tasks per exit session.
    ///
    /// `None` (default) lets the implementation choose automatically.
    #[serde(default)]
    pub udp_rx_parallelism: Option<NonZeroUsize>,

    /// Terms on which Sessions are admitted, per class of target.
    ///
    /// Rules are tried in order and the **first match wins**, so write the specific ones above the
    /// general ones, as in a firewall. A target matching no rule is admitted on the node's own
    /// configured terms, which is what every target gets when this list is empty.
    ///
    /// These decide what a Session *costs*, not whether the target may be reached at all — that
    /// remains [`target_allow_list`](Self::target_allow_list), which is checked later, once the target
    /// is resolved. A rule is matched against the unsealed target before the Session exists.
    ///
    /// Defaults to empty.
    #[serde(default)]
    #[validate(nested)]
    pub session_admission_rules: Vec<SessionAdmissionRule>,
}

/// Terms on which Sessions to one class of target are admitted.
///
/// Every term other than `target` is optional and unset means "leave the node's configured value
/// alone", so a rule states only what it changes.
#[serde_as]
#[derive(
    Clone, Debug, Eq, PartialEq, smart_default::SmartDefault, serde::Deserialize, serde::Serialize, validator::Validate,
)]
#[serde(deny_unknown_fields)]
#[validate(schema(function = "validate_admission_rule_quota", skip_on_field_errors = false))]
pub struct SessionAdmissionRule {
    /// Which targets this rule applies to. See [`TargetPattern`] for the grammar.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    #[default(TargetPattern::Any)]
    pub target: TargetPattern,

    /// Whether Sessions to these targets must pay (PIX), overriding the node's setting.
    ///
    /// `Some(false)` serves this class for free on a node that otherwise demands payment;
    /// `Some(true)` demands payment on a node that otherwise does not.
    #[serde(default)]
    pub enforce_pix: Option<bool>,

    /// Lower bound of the quota accepted for these targets, in bytes.
    ///
    /// **Narrows only.** The node's configured quota range is the envelope — it is validated at
    /// startup against the deadlines and reconstructor memory it implies — and this is intersected
    /// with it rather than replacing it. Widening a class beyond the node's range is done by
    /// configuring a wider node range and narrowing the other classes.
    #[serde(default)]
    pub quota_range_min: Option<u64>,

    /// Upper bound of the quota accepted for these targets, in bytes. Narrows only; see
    /// [`quota_range_min`](Self::quota_range_min).
    #[serde(default)]
    pub quota_range_max: Option<u64>,
}

/// Rejects a rule whose quota bounds exclude every quota, which is a typo rather than a policy.
///
/// Only the bounds *within* one rule, because the node's own quota range is not part of this
/// configuration — it lives with the transport that owns the deadlines and reconstructor memory it
/// implies. A rule that does not overlap that range has the same effect as a crossed one and cannot
/// be caught here; the transport warns once per Session when the intersection comes out empty,
/// naming both ranges.
fn validate_admission_rule_quota(rule: &SessionAdmissionRule) -> Result<(), validator::ValidationError> {
    if let (Some(min), Some(max)) = (rule.quota_range_min, rule.quota_range_max)
        && min > max
    {
        let mut error = validator::ValidationError::new("empty quota range");
        error.message = Some(
            format!(
                "rule for '{}' has quota_range_min {min} above quota_range_max {max}, which admits nothing",
                rule.target
            )
            .into(),
        );
        return Err(error);
    }
    Ok(())
}

/// Rejects a name in the allow list that no host can have.
///
/// Such an entry matches nothing, so the targets it was written to allow are denied without a word
/// of explanation. The case worth catching is an IPv4 address missing a number, such as
/// `172.30.0:8000`, which `IpOrHost` takes for a name.
fn validate_target_allow_list(list: &HashSet<IpOrHost>) -> Result<(), validator::ValidationError> {
    let mut unusable: Vec<String> = list
        .iter()
        .filter_map(|entry| match entry {
            IpOrHost::Dns(name, _) => dns_entry_problem(name).map(|problem| format!("'{entry}' ({problem})")),
            IpOrHost::Ip(_) => None,
        })
        .collect();

    if unusable.is_empty() {
        return Ok(());
    }

    // A set iterates in arbitrary order; sorted, one config always reports one message.
    unusable.sort();
    let mut error = validator::ValidationError::new("unusable allow list entry");
    error.message = Some(format!("no host name can match {}", unusable.join(", ")).into());
    Err(error)
}

/// Why `name` cannot be the name of a host, if it cannot.
fn dns_entry_problem(name: &str) -> Option<&'static str> {
    let name = without_root_dot(name);

    if name.is_empty() {
        Some("empty host name")
    } else if !is_dns_charset(name) {
        Some("not a DNS name")
    } else if name.split('.').any(str::is_empty) {
        Some("empty label")
    } else if name
        .rsplit('.')
        .next()
        .is_some_and(|label| label.bytes().all(|b| b.is_ascii_digit()))
    {
        Some("last label is numeric, like a mistyped IPv4 address")
    } else {
        None
    }
}

fn default_target_retry_delay() -> Duration {
    Duration::from_secs(2)
}

fn default_entry_listen_host() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn default_max_tcp_target_retries() -> u32 {
    10
}

fn just_true() -> bool {
    true
}
