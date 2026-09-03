use std::{collections::HashSet, net::SocketAddr, num::NonZeroUsize, time::Duration};

use serde_with::serde_as;
// In scope for the `#[validate(nested)]` on `session_admission_rules`, whose generated code calls
// `Validate::validate` on the `Vec`.
use validator::Validate;

use crate::target_pattern::TargetPattern;

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

    /// Enforces only the given target addresses (after DNS resolution).
    ///
    /// This is used only if `use_target_allow_list` is set to `true`.
    /// If left empty (and `use_target_allow_list` is `true`), the node will not act as an Exit node.
    ///
    /// Defaults to empty.
    #[serde(default)]
    #[serde_as(as = "HashSet<serde_with::DisplayFromStr>")]
    pub target_allow_list: HashSet<SocketAddr>,

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
    /// remains [`target_allow_list`](Self::target_allow_list), which is checked later, against
    /// resolved addresses. A rule is matched against the unsealed target before the Session exists.
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
