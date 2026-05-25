//! Live Kubernetes watch (kube-rs). One reflector store per watched resource;
//! any change pokes a channel, and a 300ms-debounced task rebuilds all tables
//! from the current store state. Replaces the four client-go watch loops +
//! `sync.Map`s + per-resource debounces in the Go controller with reflector
//! stores (which also handle relist/resync for free).

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::core::v1::{Endpoints, Secret, Service};
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::{reflector, watcher, WatchStreamExt};
use kube::{Api, Client};
use tokio::sync::mpsc;

use super::Snapshot;
use crate::shared::Shared;

/// Build a reflector store for `$ty`, drive it on a background task, and poke
/// `$tx` on every successful event. Returns the read handle (`Store`).
macro_rules! reflect {
    ($ty:ty, $client:expr, $ns:expr, $tx:expr) => {{
        let api: Api<$ty> = match &$ns {
            Some(ns) => Api::namespaced($client.clone(), ns),
            None => Api::all($client.clone()),
        };
        let (reader, writer) = reflector::store::<$ty>();
        let stream = reflector::reflector(writer, watcher(api, watcher::Config::default()))
            .default_backoff();
        let tx = $tx.clone();
        let kind = stringify!($ty);
        tokio::spawn(async move {
            futures::pin_mut!(stream);
            while let Some(event) = stream.next().await {
                match event {
                    // Non-blocking: this channel is an edge "something changed,
                    // coalesce a reload" signal. Blocking here (tx.send().await on
                    // a bounded channel) deadlocks during the initial sync — rx is
                    // not drained until after wait_until_ready(), so a real cluster
                    // (many objects) fills the buffer, the reflectors stop polling,
                    // the initial list never finishes, and sync never completes.
                    // A dropped tick is harmless: a full buffer already means a
                    // reload is pending.
                    Ok(_) => {
                        let _ = tx.try_send(());
                    }
                    // surface watch failures (RBAC 403, API TLS, etc.) — these
                    // were previously swallowed, leaving an empty router/certs.
                    Err(e) => eprintln!("[watch] {kind} error: {e}"),
                }
            }
        });
        reader
    }};
}

/// Watch the cluster and keep `shared` reloaded. Runs until the process exits.
pub async fn run(shared: Arc<Shared>, namespace: Option<String>) -> Result<(), kube::Error> {
    let client = Client::try_default().await?;
    eprintln!(
        "[watch] connected to cluster; watching namespace={}",
        namespace.as_deref().unwrap_or("<all>")
    );
    let (tx, mut rx) = mpsc::channel::<()>(32);

    let ingresses = reflect!(Ingress, client, namespace, tx);
    let services = reflect!(Service, client, namespace, tx);
    let endpoints = reflect!(Endpoints, client, namespace, tx);
    let secrets = reflect!(Secret, client, namespace, tx);

    let snapshot = || Snapshot {
        ingresses: ingresses.state(),
        services: services.state(),
        endpoints: endpoints.state(),
        secrets: secrets.state(),
    };

    // initial sync: wait for each store to fill, then do the first reload
    let _ = ingresses.wait_until_ready().await;
    let _ = services.wait_until_ready().await;
    let _ = endpoints.wait_until_ready().await;
    let _ = secrets.wait_until_ready().await;
    eprintln!("[watch] initial sync complete");
    shared.rebuild(&snapshot());

    // subsequent reloads, debounced: coalesce a burst of events into one rebuild
    // after a 300ms quiet window (matches the Go debounce interval).
    while rx.recv().await.is_some() {
        // coalesce: keep draining while events keep arriving within the 300ms
        // window; stop on a quiet window (timeout) or a closed channel.
        while let Ok(Some(())) = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await {
        }
        shared.rebuild(&snapshot());
    }

    Ok(())
}
