//! Enforcement of the [`target_allow_list`](crate::config::SessionIpForwardingConfig::target_allow_list).

use std::{collections::HashSet, future::Future, net::SocketAddr};

use hopr_utils::network_types::prelude::IpOrHost;

use crate::{config::SessionIpForwardingConfig, target_pattern::without_root_dot};

/// Whether a Session may be forwarded to `target`, which has been resolved to `resolved`.
///
/// That is the case if the allow list is off, if `target` is a name the list holds on the same port,
/// or if every address in `resolved` is listed, either literally or as what one of the list's names
/// resolves to right now. `resolve` looks those names up and is not called when literal entries
/// settle the matter.
pub(crate) async fn is_allowed<R, Fut>(
    cfg: &SessionIpForwardingConfig,
    target: &IpOrHost,
    resolved: &[SocketAddr],
    resolve: R,
) -> bool
where
    R: Fn(IpOrHost) -> Fut,
    Fut: Future<Output = std::io::Result<Vec<SocketAddr>>>,
{
    if !cfg.use_target_allow_list {
        return true;
    }
    let list = &cfg.target_allow_list;

    // The operator paired this very name with this port, so where it leads is theirs to decide.
    if let IpOrHost::Dns(name, port) = target
        && let Some(entry) = list.iter().find(|entry| {
            matches!(entry, IpOrHost::Dns(listed, listed_port)
                if listed_port == port && without_root_dot(listed).eq_ignore_ascii_case(without_root_dot(name)))
        })
    {
        tracing::debug!(%entry, "target allowed by a name on the target allow list, accepting the target");
        return true;
    }

    let is_listed = |addr: &SocketAddr| list.contains(&IpOrHost::Ip(*addr));

    // A lookup costs a round trip, so it waits until a literal entry has failed to settle the matter.
    let by_name = if resolved.iter().all(is_listed) {
        HashSet::new()
    } else {
        resolve_listed_names(list, resolved, &resolve).await
    };

    for addr in resolved {
        if !is_listed(addr) && !by_name.contains(addr) {
            tracing::error!(%addr, "address not allowed by the target allow list, denying the target");
            return false;
        }
        tracing::debug!(%addr, "address allowed by the target allow list, accepting the target");
    }
    true
}

/// Resolves, concurrently, the names in `list` that could account for one of the `wanted` addresses.
///
/// A name that does not resolve contributes nothing: what depended on it is denied, which is the
/// safe way to fail, and what other entries cover is unaffected.
async fn resolve_listed_names<R, Fut>(
    list: &HashSet<IpOrHost>,
    wanted: &[SocketAddr],
    resolve: &R,
) -> HashSet<SocketAddr>
where
    R: Fn(IpOrHost) -> Fut,
    Fut: Future<Output = std::io::Result<Vec<SocketAddr>>>,
{
    // A name listed on another port can only lead to addresses on that port.
    let lookups = list
        .iter()
        .filter(|entry| entry.is_dns() && wanted.iter().any(|addr| addr.port() == entry.port()))
        .map(|entry| async move {
            resolve(entry.clone()).await.unwrap_or_else(|error| {
                tracing::warn!(%entry, %error, "name on the target allow list does not resolve, ignoring it");
                Vec::new()
            })
        });

    futures::future::join_all(lookups).await.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::IpAddr,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use anyhow::Context;

    use super::*;

    /// A resolver answering from a table. It counts the lookups the allow list makes of it, which
    /// is why the target itself is resolved through [`Dns::answer`] instead: that is `process`'s
    /// lookup, not the allow list's.
    #[derive(Default)]
    struct Dns {
        records: Mutex<HashMap<String, Vec<IpAddr>>>,
        lookups: AtomicUsize,
    }

    impl Dns {
        fn new(records: &[(&str, &[&str])]) -> Self {
            let dns = Self::default();
            for (name, ips) in records {
                dns.point(name, ips);
            }
            dns
        }

        /// Makes `name` lead to `ips`, replacing wherever it led before.
        fn point(&self, name: &str, ips: &[&str]) {
            let ips = ips.iter().map(|ip| ip.parse().expect("a test address")).collect();
            self.records
                .lock()
                .expect("the table is never poisoned")
                .insert(name.to_ascii_lowercase(), ips);
        }

        /// Where `host` leads, which for a name is a table lookup that ignores case and the root dot
        /// like DNS does.
        fn answer(&self, host: &IpOrHost) -> std::io::Result<Vec<SocketAddr>> {
            match host {
                IpOrHost::Ip(addr) => Ok(vec![*addr]),
                IpOrHost::Dns(name, port) => self
                    .records
                    .lock()
                    .expect("the table is never poisoned")
                    .get(&without_root_dot(name).to_ascii_lowercase())
                    .map(|ips| ips.iter().map(|ip| SocketAddr::new(*ip, *port)).collect())
                    .ok_or_else(|| std::io::Error::other(format!("no records for {name}"))),
            }
        }

        /// The resolver handed to the allow list.
        async fn resolve(&self, host: IpOrHost) -> std::io::Result<Vec<SocketAddr>> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            self.answer(&host)
        }

        fn lookups(&self) -> usize {
            self.lookups.load(Ordering::SeqCst)
        }
    }

    fn config(entries: &[&str]) -> anyhow::Result<SessionIpForwardingConfig> {
        Ok(SessionIpForwardingConfig {
            target_allow_list: entries
                .iter()
                .map(|entry| {
                    entry
                        .parse()
                        .with_context(|| format!("parsing allow list entry {entry}"))
                })
                .collect::<anyhow::Result<_>>()?,
            ..Default::default()
        })
    }

    /// Asks the allow list about `target` the way `process` does: resolve it, then check the result.
    async fn allowed(cfg: &SessionIpForwardingConfig, target: &str, dns: &Dns) -> anyhow::Result<bool> {
        let target: IpOrHost = target.parse().context("parsing the target")?;
        let resolved = dns.answer(&target).context("resolving the target")?;
        Ok(is_allowed(cfg, &target, &resolved, |name| dns.resolve(name)).await)
    }

    #[tokio::test]
    async fn a_disabled_list_allows_everything_without_a_lookup() -> anyhow::Result<()> {
        let cfg = SessionIpForwardingConfig {
            use_target_allow_list: false,
            ..config(&["gnosisvpnserver:8000"])?
        };
        let dns = Dns::new(&[("elsewhere.example", &["203.0.113.7"])]);

        assert!(allowed(&cfg, "elsewhere.example:443", &dns).await?);
        assert!(allowed(&cfg, "203.0.113.7:22", &dns).await?);
        assert_eq!(dns.lookups(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn an_empty_list_allows_nothing() -> anyhow::Result<()> {
        let cfg = config(&[])?;
        let dns = Dns::new(&[("elsewhere.example", &["203.0.113.7"])]);

        assert!(!allowed(&cfg, "203.0.113.7:443", &dns).await?);
        assert!(!allowed(&cfg, "elsewhere.example:443", &dns).await?);
        assert_eq!(dns.lookups(), 0, "there is no name to look up");
        Ok(())
    }

    #[tokio::test]
    async fn a_listed_address_is_allowed_without_a_lookup() -> anyhow::Result<()> {
        let cfg = config(&["10.0.0.5:8000", "gnosisvpnserver:8000"])?;
        let dns = Dns::new(&[("gnosisvpnserver", &["10.0.0.9"]), ("internal.example", &["10.0.0.5"])]);

        assert!(allowed(&cfg, "10.0.0.5:8000", &dns).await?);
        assert!(
            allowed(&cfg, "internal.example:8000", &dns).await?,
            "a name that leads to a listed address is allowed, as it always was"
        );
        assert_eq!(
            dns.lookups(),
            0,
            "the literal entry settles both, so the listed name is left alone"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_unlisted_address_is_refused() -> anyhow::Result<()> {
        let cfg = config(&["10.0.0.5:8000"])?;
        let dns = Dns::default();

        assert!(!allowed(&cfg, "10.0.0.6:8000", &dns).await?);
        assert!(
            !allowed(&cfg, "10.0.0.5:9000", &dns).await?,
            "the port is part of the entry"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_listed_name_allows_that_name_wherever_it_leads() -> anyhow::Result<()> {
        let cfg = config(&["gnosisvpnserver:8000"])?;
        let dns = Dns::new(&[("gnosisvpnserver", &["172.30.0.2"])]);

        assert!(allowed(&cfg, "gnosisvpnserver:8000", &dns).await?);

        dns.point("gnosisvpnserver", &["172.30.0.9", "fd00::9"]);
        assert!(
            allowed(&cfg, "gnosisvpnserver:8000", &dns).await?,
            "the name is what was allowed, not the address it had when the node started"
        );
        assert_eq!(
            dns.lookups(),
            0,
            "the target is the entry, so there is nothing to look up"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_listed_name_is_matched_regardless_of_case_and_root_dot() -> anyhow::Result<()> {
        let dns = Dns::new(&[("gnosisvpnserver", &["172.30.0.2"])]);

        // However the operator wrote it…
        for entry in ["gnosisvpnserver:8000", "GnosisVPNServer:8000", "gnosisvpnserver.:8000"] {
            let cfg = config(&[entry])?;
            // …and however the peer did.
            for target in ["gnosisvpnserver:8000", "GNOSISVPNSERVER:8000", "gnosisvpnserver.:8000"] {
                assert!(
                    allowed(&cfg, target, &dns).await?,
                    "entry {entry} against target {target}"
                );
            }
        }
        assert_eq!(dns.lookups(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_listed_name_is_tied_to_its_port() -> anyhow::Result<()> {
        let cfg = config(&["gnosisvpnserver:8000"])?;
        let dns = Dns::new(&[("gnosisvpnserver", &["172.30.0.2"])]);

        assert!(!allowed(&cfg, "gnosisvpnserver:9999", &dns).await?);
        assert!(!allowed(&cfg, "172.30.0.2:9999", &dns).await?);
        assert_eq!(
            dns.lookups(),
            0,
            "an entry on another port cannot account for either target"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_raw_address_is_allowed_when_a_listed_name_leads_to_it() -> anyhow::Result<()> {
        let cfg = config(&["gnosisvpnserver:8000"])?;
        let dns = Dns::new(&[("gnosisvpnserver", &["172.30.0.2", "fd00::2"])]);

        assert!(allowed(&cfg, "172.30.0.2:8000", &dns).await?);
        assert!(allowed(&cfg, "[fd00::2]:8000", &dns).await?);
        assert!(!allowed(&cfg, "172.30.0.3:8000", &dns).await?);
        assert_eq!(dns.lookups(), 3, "each request looks the name up for itself");
        Ok(())
    }

    #[tokio::test]
    async fn a_listed_name_is_resolved_again_for_every_request() -> anyhow::Result<()> {
        let cfg = config(&["gnosisvpnserver:8000"])?;
        let dns = Dns::new(&[("gnosisvpnserver", &["172.30.0.2"])]);

        assert!(allowed(&cfg, "172.30.0.2:8000", &dns).await?);

        // The container is replaced and comes back at another address.
        dns.point("gnosisvpnserver", &["172.30.0.9"]);

        assert!(
            !allowed(&cfg, "172.30.0.2:8000", &dns).await?,
            "the old address is no longer the name's"
        );
        assert!(allowed(&cfg, "172.30.0.9:8000", &dns).await?);
        Ok(())
    }

    #[tokio::test]
    async fn another_name_is_allowed_when_it_leads_to_a_listed_names_address() -> anyhow::Result<()> {
        let cfg = config(&["gnosisvpnserver:8000"])?;
        let dns = Dns::new(&[
            ("gnosisvpnserver", &["172.30.0.2"]),
            ("alias.internal", &["172.30.0.2"]),
            ("other.internal", &["172.30.0.7"]),
        ]);

        assert!(allowed(&cfg, "alias.internal:8000", &dns).await?);
        assert!(!allowed(&cfg, "other.internal:8000", &dns).await?);
        Ok(())
    }

    #[tokio::test]
    async fn a_listed_name_that_does_not_resolve_is_skipped_rather_than_fatal() -> anyhow::Result<()> {
        let dns = Dns::new(&[("gnosisvpnserver", &["172.30.0.2"])]);

        let cfg = config(&["gone.example:8000", "gnosisvpnserver:8000"])?;
        assert!(
            allowed(&cfg, "172.30.0.2:8000", &dns).await?,
            "the entry that does resolve still counts"
        );
        assert_eq!(dns.lookups(), 2, "both names are tried");

        let only_gone = config(&["gone.example:8000"])?;
        assert!(
            !allowed(&only_gone, "172.30.0.2:8000", &dns).await?,
            "with nothing left to allow the address, it is refused"
        );
        Ok(())
    }

    #[tokio::test]
    async fn every_address_a_target_resolves_to_must_be_allowed() -> anyhow::Result<()> {
        let cfg = config(&["10.0.0.1:8000", "gnosisvpnserver:8000"])?;
        let dns = Dns::new(&[
            ("gnosisvpnserver", &["10.0.0.2"]),
            ("pool.internal", &["10.0.0.1", "10.0.0.2"]),
            ("mixed.internal", &["10.0.0.1", "10.0.0.3"]),
        ]);

        assert!(
            allowed(&cfg, "pool.internal:8000", &dns).await?,
            "one address is listed and the other is the listed name's"
        );
        assert!(
            !allowed(&cfg, "mixed.internal:8000", &dns).await?,
            "TCP may connect to any of them, so one stray address refuses the target"
        );
        Ok(())
    }

    #[tokio::test]
    async fn only_names_on_the_targets_port_are_looked_up() -> anyhow::Result<()> {
        let cfg = config(&["a.example:80", "b.example:8000"])?;
        let dns = Dns::new(&[("a.example", &["10.0.0.1"]), ("b.example", &["10.0.0.2"])]);

        assert!(allowed(&cfg, "10.0.0.2:8000", &dns).await?);
        assert_eq!(dns.lookups(), 1);
        Ok(())
    }
}
