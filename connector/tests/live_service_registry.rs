//! Checks the service registry read path against a real Blokli instead of the test client.
//!
//! These are ignored by default because they need a server. Start one and run them with:
//!
//! ```shell
//! docker run -d --name blokli-probe -p 18080:8080 \
//!   europe-west3-docker.pkg.dev/hoprassociation/docker-images/bloklid-anvil:latest-main
//! # wait until {"data":{"version":"...","health":"ok"}}
//! BLOKLI_URL=http://localhost:18080 cargo test -p hopr-chain-connector --test live_service_registry -- --ignored
//! ```
//!
//! Pin a digest rather than `latest-main` only if it is known to carry the registry API: the digest
//! referenced by `hoprd/localcluster/docker-compose.yml` predates it and exposes no registry
//! queries at all.

use blokli_client::{BlokliClient, BlokliClientConfig, api::BlokliQueryClient, exports::Url};
use futures::StreamExt;
use hopr_api::chain::{ChainReadServiceOperations, ServiceSelector};
use hopr_chain_connector::HoprBlockchainReader;

fn reader() -> anyhow::Result<HoprBlockchainReader<BlokliClient>> {
    let base: Url = std::env::var("BLOKLI_URL")
        .unwrap_or_else(|_| "http://localhost:18080".into())
        .parse()?;

    Ok(HoprBlockchainReader::new(BlokliClient::new(
        base,
        BlokliClientConfig::default(),
    )))
}

/// The reason the per-type fan-out was removed: Blokli answers an unfiltered enumeration rather
/// than rejecting it.
///
/// `blokli-client` documents the opposite on `ServiceSelector` - that `query_services` "requires a
/// narrower selector" - which is what the fan-out was written for. Nothing in the client enforces
/// it, and the server does not either.
#[tokio::test]
#[ignore = "requires a running Blokli"]
async fn an_unfiltered_registry_query_is_answered_rather_than_rejected() -> anyhow::Result<()> {
    let reader = reader()?;

    // The claim under test is that this does not fail. An empty registry is a valid answer.
    let entries = reader
        .stream_services(ServiceSelector::default())?
        .collect::<Vec<_>>()
        .await;
    let live = reader
        .stream_services(ServiceSelector::default().with_live_only(true))?
        .collect::<Vec<_>>()
        .await;

    // Counting takes the other route, straight to Blokli, and must agree with the enumeration.
    assert_eq!(entries.len(), reader.count_services(ServiceSelector::default()).await?);
    assert_eq!(
        live.len(),
        reader
            .count_services(ServiceSelector::default().with_live_only(true))
            .await?
    );

    // A live entry is by definition also an entry, so the unfiltered read cannot be the narrower.
    assert!(live.len() <= entries.len());

    // Printed because an empty registry passes everything above vacuously.
    println!("enumerated {} entries, {} of them live", entries.len(), live.len());

    Ok(())
}

/// Every entry the enumeration returns must survive the conversion, and must be reachable through
/// the narrower selectors as well.
#[tokio::test]
#[ignore = "requires a running Blokli"]
async fn every_enumerated_entry_is_reachable_through_a_narrow_selector() -> anyhow::Result<()> {
    let reader = reader()?;

    let entries = reader
        .stream_services(ServiceSelector::default())?
        .collect::<Vec<_>>()
        .await;

    println!("checking {} enumerated entries", entries.len());
    for entry in &entries {
        let by_type_and_node = reader
            .stream_services(
                ServiceSelector::default()
                    .with_service_type(entry.service_type)
                    .with_node(entry.node),
            )?
            .collect::<Vec<_>>()
            .await;
        assert_eq!(vec![entry.clone()], by_type_and_node);

        // The type an entry is registered under must itself be readable.
        assert!(
            reader.get_service_type_config(entry.service_type).await?.is_some(),
            "service type {} of {} is not registered",
            entry.service_type,
            entry.node
        );
    }

    Ok(())
}

/// The registry-wide configuration is a plain read, and the connector needs it to fund a
/// registration correctly.
#[tokio::test]
#[ignore = "requires a running Blokli"]
async fn the_registry_wide_configuration_is_readable() -> anyhow::Result<()> {
    let reader = reader()?;

    let config = reader.get_service_registry_config().await?;
    assert_ne!(
        hopr_api::types::primitive::prelude::Address::default(),
        config.node_safe_registry,
        "the registry must point at a node-Safe registry"
    );

    Ok(())
}

/// Pins that the client sends the unfiltered query as such, rather than the server accepting it
/// only because the client narrowed it.
#[tokio::test]
#[ignore = "requires a running Blokli"]
async fn the_client_sends_an_unfiltered_query_for_the_any_selector() -> anyhow::Result<()> {
    let base: Url = std::env::var("BLOKLI_URL")
        .unwrap_or_else(|_| "http://localhost:18080".into())
        .parse()?;
    let client = BlokliClient::new(base, BlokliClientConfig::default());

    client.query_services(blokli_client::api::ServiceSelector::Any).await?;
    client
        .query_live_services(blokli_client::api::ServiceSelector::Any)
        .await?;
    client.count_services(blokli_client::api::ServiceSelector::Any).await?;

    Ok(())
}
