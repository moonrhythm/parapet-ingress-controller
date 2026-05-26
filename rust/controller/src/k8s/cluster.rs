//! Live Kubernetes watch (kube-rs). One reflector store per watched resource;
//! any change pokes a channel, and a 300ms-debounced task rebuilds all tables
//! from the current store state. Replaces the four client-go watch loops +
//! `sync.Map`s + per-resource debounces in the Go controller with reflector
//! stores (which also handle relist/resync for free).

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::core::v1::{ConfigMap, Endpoints, Secret, Service};
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::{reflector, watcher, WatchStreamExt};
use kube::{Api, Client};
use tokio::sync::mpsc;

use super::Snapshot;
use crate::shared::Shared;
use crate::waf::WAF_LABEL_KEY;

/// WAF watch settings, passed to [`run`] when `WAF_ENABLED=true`. `None` skips
/// the ConfigMap watch entirely (zero cost when the WAF is off).
pub struct WafWatch {
    /// Controller's own namespace; bounds where the global ruleset may live.
    pub pod_namespace: String,
}

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
pub async fn run(
    shared: Arc<Shared>,
    namespace: Option<String>,
    waf: Option<WafWatch>,
) -> Result<(), kube::Error> {
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

    // WAF ConfigMaps run on a *separate* reflector + debounce loop: rule edits
    // recompile the rulesets but must never rebuild the router (decoupled
    // lifecycle). Only started when WAF_ENABLED.
    if let Some(w) = waf {
        spawn_waf_watch(
            client.clone(),
            namespace.clone(),
            shared.clone(),
            w.pod_namespace,
        );
    }

    let snapshot = || Snapshot {
        ingresses: ingresses.state(),
        services: services.state(),
        endpoints: endpoints.state(),
        secrets: secrets.state(),
        // WAF ConfigMaps are watched on a separate reflector (see spawn_waf_watch),
        // decoupled from the router rebuild, so they're not part of the snapshot.
        configmaps: Vec::new(),
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

/// Drive a label-filtered ConfigMap reflector and recompile the WAF rulesets on
/// every change (300ms-debounced), independent of the router reconcile.
fn spawn_waf_watch(
    client: Client,
    namespace: Option<String>,
    shared: Arc<Shared>,
    pod_namespace: String,
) {
    let api: Api<ConfigMap> = match &namespace {
        Some(ns) => Api::namespaced(client, ns),
        None => Api::all(client),
    };
    let (reader, writer) = reflector::store::<ConfigMap>();
    let cfg = watcher::Config::default().labels(WAF_LABEL_KEY);
    let stream = reflector::reflector(writer, watcher(api, cfg)).default_backoff();
    let (tx, mut rx) = mpsc::channel::<()>(32);

    // driver: mirror events into the store and poke the debounce channel
    tokio::spawn(async move {
        futures::pin_mut!(stream);
        while let Some(event) = stream.next().await {
            match event {
                Ok(_) => {
                    let _ = tx.try_send(());
                }
                Err(e) => eprintln!("[watch] ConfigMap error: {e}"),
            }
        }
    });

    // reconcile loop: initial sync, then debounced rebuilds of the WAF rulesets
    tokio::spawn(async move {
        let _ = reader.wait_until_ready().await;
        eprintln!("[watch] waf: initial configmap sync complete");
        crate::waf::reconcile_configmaps(&shared.waf, &reader.state(), &pod_namespace);
        while rx.recv().await.is_some() {
            while let Ok(Some(())) =
                tokio::time::timeout(Duration::from_millis(300), rx.recv()).await
            {}
            crate::waf::reconcile_configmaps(&shared.waf, &reader.state(), &pod_namespace);
        }
    });
}
