//! Static filesystem backend: load Kubernetes manifests (YAML/JSON, possibly
//! multi-document, `List` objects supported) from a directory into a
//! [`Snapshot`]. Mirrors `k8s/fs.go`; used for local dev and tests. No watching.

use std::path::Path;
use std::sync::Arc;

use k8s_openapi::api::core::v1::{Endpoints, Secret, Service};
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use serde::Deserialize;
use serde_yaml::Value;

use super::Snapshot;

/// Load every file in `dir` (non-recursive, like the Go walk over a flat dir).
pub fn load_dir(dir: &Path) -> std::io::Result<Snapshot> {
    let mut snap = Snapshot::default();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            continue;
        }
        // only manifest files; skip stray non-YAML files (e.g. scripts), which
        // would otherwise be fed to the YAML parser
        let is_manifest = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yaml" | "yml" | "json")
        );
        if !is_manifest {
            continue;
        }
        let data = std::fs::read_to_string(&path)?;
        add_documents(&mut snap, &data);
    }
    Ok(snap)
}

pub fn load_str(data: &str) -> Snapshot {
    let mut snap = Snapshot::default();
    add_documents(&mut snap, data);
    snap
}

fn add_documents(snap: &mut Snapshot, data: &str) {
    for doc in serde_yaml::Deserializer::from_str(data) {
        if let Ok(v) = Value::deserialize(doc) {
            add_value(snap, v);
        }
    }
}

fn add_value(snap: &mut Snapshot, v: Value) {
    let kind = v.get("kind").and_then(Value::as_str).unwrap_or("");

    match kind {
        "List" => {
            if let Some(items) = v.get("items").and_then(Value::as_sequence) {
                for it in items.iter().cloned() {
                    add_value(snap, it);
                }
            }
        }
        "Ingress" => push(&mut snap.ingresses, v, |o: &mut Ingress| &mut o.metadata),
        "Service" => push(&mut snap.services, v, |o: &mut Service| &mut o.metadata),
        "Endpoints" => push(&mut snap.endpoints, v, |o: &mut Endpoints| &mut o.metadata),
        "Secret" => push(&mut snap.secrets, v, |o: &mut Secret| &mut o.metadata),
        _ => {}
    }
}

fn push<T, F>(out: &mut Vec<Arc<T>>, v: Value, meta: F)
where
    T: for<'de> Deserialize<'de>,
    F: Fn(&mut T) -> &mut ObjectMeta,
{
    if let Ok(mut obj) = serde_yaml::from_value::<T>(v) {
        let m = meta(&mut obj);
        if m.namespace.as_deref().unwrap_or("").is_empty() {
            m.namespace = Some("default".to_string());
        }
        out.push(Arc::new(obj));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconcile::RouteKind;
    use crate::router::Match;
    use crate::shared::Shared;

    const MANIFEST: &str = r#"
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
spec:
  ingressClassName: parapet
  rules:
    - host: example.com
      http:
        paths:
          - path: /app
            pathType: Prefix
            backend:
              service:
                name: web
                port:
                  number: 80
---
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  ports:
    - port: 80
      targetPort: 8080
---
apiVersion: v1
kind: Endpoints
metadata:
  name: web
subsets:
  - addresses:
      - ip: 10.0.0.1
"#;

    #[test]
    fn parses_multi_document_manifest() {
        let snap = load_str(MANIFEST);
        assert_eq!(snap.ingresses.len(), 1);
        assert_eq!(snap.services.len(), 1);
        assert_eq!(snap.endpoints.len(), 1);
        // namespace autofilled to "default"
        assert_eq!(
            snap.ingresses[0].metadata.namespace.as_deref(),
            Some("default")
        );
    }

    #[test]
    fn fs_snapshot_drives_shared_end_to_end() {
        let snap = load_str(MANIFEST);
        let shared = Shared::new("parapet", false);
        shared.rebuild(&snap);

        // routing
        let router = shared.router.load();
        match router.lookup("example.com", "/app/x") {
            Match::Found(e) => {
                assert_eq!(e.pattern, "example.com/app/");
                assert_eq!(
                    e.kind,
                    RouteKind::Service {
                        target: "web.default.svc.cluster.local:80".into(),
                        scheme: crate::reconcile::UpstreamScheme::Http,
                    }
                );
            }
            other => panic!("expected Found, got {other:?}"),
        }

        // service+endpoint resolution
        assert_eq!(
            shared
                .route_table
                .lookup("web.default.svc.cluster.local:80")
                .as_deref(),
            Some("10.0.0.1:8080")
        );

        // metric-cardinality bound: the router's host is known; anything else
        // (a random-Host flood) is not, and collapses to the sentinel label.
        assert!(shared.is_known_host("example.com"));
        assert!(!shared.is_known_host("evil.attacker.example"));
    }

    #[test]
    fn load_dir_reads_files() {
        let dir = std::env::temp_dir().join(format!(
            "parapet-fs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.yaml"), MANIFEST).unwrap();

        let snap = load_dir(&dir).unwrap();
        assert_eq!(snap.ingresses.len(), 1);
        assert_eq!(snap.services.len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }
}
