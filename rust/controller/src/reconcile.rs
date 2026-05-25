//! Build the routing/cert state from Kubernetes objects. Port of the
//! `reloadIngress / reloadService / reloadEndpoint / reloadSecret` logic in
//! `controller.go`, expressed as pure functions over `k8s-openapi` types so it
//! can be tested with hand-built objects (no cluster). Tests track
//! `controller_reload_test.go`.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use k8s_openapi::api::core::v1::{Endpoints, Secret, Service};
use k8s_openapi::api::networking::v1::{Ingress, IngressServiceBackend};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

use crate::cert::LoadedCert;
use crate::config::{RouteConfig, UpstreamProtocol};
use crate::route::Rrlb;
use crate::router::Router;

pub fn build_host(namespace: &str, name: &str) -> String {
    format!("{name}.{namespace}.svc.cluster.local")
}

pub fn build_host_port(namespace: &str, name: &str, port: i32) -> String {
    format!("{name}.{namespace}.svc.cluster.local:{port}")
}

/// A resolved router entry. `pattern` echoes the registration key so callers
/// (and tests) can recover "which pattern matched" (like Go's `mux.Handler`).
/// `config` is the parsed annotations of the owning ingress, shared across all
/// of its routes and applied by the proxy phases.
#[derive(Debug, PartialEq)]
pub struct RouteEntry {
    pub pattern: String,
    pub kind: RouteKind,
    pub config: Arc<RouteConfig>,
    /// ingress/service identity, for access-log fields and metric labels
    pub meta: RouteMeta,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RouteKind {
    /// Proxy to a service: `target` is the service DNS `host:port`, `scheme` is
    /// the resolved upstream protocol (see [`UpstreamScheme`]).
    Service {
        target: String,
        scheme: UpstreamScheme,
    },
    /// Host-level redirect from a `redirect` annotation rule.
    Redirect { status: u16, target: String },
}

/// The wire protocol the proxy uses to reach an upstream, resolved once at
/// reconcile time from the service port's `appProtocol` and the route's
/// `upstream-protocol` annotation (see [`resolve_scheme`]). Replaces the Go
/// controller's request-time string matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpstreamScheme {
    #[default]
    Http,
    Https,
    H2c,
}

/// Resolve the effective upstream scheme. The service port's `appProtocol`
/// (`app_protocol`) wins when it names a known scheme; an unset `appProtocol`
/// falls back to the `upstream-protocol` annotation; anything else is plain
/// HTTP. Mirrors the Go controller's resolution order exactly.
pub fn resolve_scheme(app_protocol: &str, annotation: &UpstreamProtocol) -> UpstreamScheme {
    match app_protocol {
        "h2c" => UpstreamScheme::H2c,
        "https" => UpstreamScheme::Https,
        "" => match annotation {
            UpstreamProtocol::Https => UpstreamScheme::Https,
            UpstreamProtocol::Http => UpstreamScheme::Http,
        },
        _ => UpstreamScheme::Http,
    }
}

#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct RouteMeta {
    pub ingress_namespace: String,
    pub ingress_name: String,
    pub service_name: String,
    pub service_type: String,
}

fn ingress_class(ing: &Ingress) -> &str {
    if let Some(c) = ing
        .spec
        .as_ref()
        .and_then(|s| s.ingress_class_name.as_deref())
    {
        return c;
    }
    ing.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get("kubernetes.io/ingress.class"))
        .map_or("", String::as_str)
}

/// Resolve the backend's port to `(appProtocol, portNumber)`.
/// Returns `None` only when a port *name* is given but doesn't exist on the
/// service (Go's `ok == false`); a numeric port always resolves.
fn backend_config(backend: &IngressServiceBackend, svc: &Service) -> Option<(String, i32)> {
    let ports = svc.spec.as_ref().and_then(|s| s.ports.as_ref());
    let port = backend.port.as_ref();

    // by name
    if let Some(name) = port
        .and_then(|p| p.name.as_deref())
        .filter(|n| !n.is_empty())
    {
        let mut found = None;
        if let Some(ports) = ports {
            for sp in ports {
                if sp.name.as_deref() == Some(name) {
                    found = Some((sp.app_protocol.clone().unwrap_or_default(), sp.port));
                }
            }
        }
        return found;
    }

    // by number
    let number = port.and_then(|p| p.number).unwrap_or(0);
    let mut protocol = String::new();
    if let Some(ports) = ports {
        for sp in ports {
            if sp.port == number {
                protocol = sp.app_protocol.clone().unwrap_or_default();
            }
        }
    }
    Some((protocol, number))
}

#[allow(clippy::too_many_arguments)]
fn register(
    routes: &mut HashMap<String, RouteEntry>,
    host: &str,
    path: &str,
    path_type: &str,
    target: &str,
    scheme: UpstreamScheme,
    config: &Arc<RouteConfig>,
    meta: &RouteMeta,
) {
    let mut put = |pattern: String| {
        routes.insert(
            pattern.clone(),
            RouteEntry {
                pattern,
                kind: RouteKind::Service {
                    target: target.to_string(),
                    scheme,
                },
                config: config.clone(),
                meta: meta.clone(),
            },
        );
    };

    match path_type {
        "Prefix" => {
            let trimmed = path.strip_suffix('/').unwrap_or(path);
            let src = format!("{host}{trimmed}");
            if path != "/" {
                put(src.clone());
            }
            put(format!("{src}/"));
        }
        "Exact" => {
            // exact at root isn't supported by ServeMux; Go falls back to host/path
            let src = if path == "/" {
                format!("{host}{path}")
            } else {
                format!("{host}{}", path.strip_suffix('/').unwrap_or(path))
            };
            put(src);
        }
        // ImplementationSpecific (and anything unknown): register as-is
        _ => put(format!("{host}{path}")),
    }
}

/// Build the request router from the current ingresses + services.
pub fn build_router(
    ingresses: &[&Ingress],
    services: &HashMap<String, &Service>,
    ingress_class_name: &str,
) -> Router<RouteEntry> {
    let mut routes: HashMap<String, RouteEntry> = HashMap::new();

    for ing in ingresses {
        if ingress_class(ing) != ingress_class_name {
            continue;
        }
        let ns = ing.metadata.namespace.as_deref().unwrap_or("");
        let ann = ing.metadata.annotations.clone().unwrap_or_default();
        let cfg = Arc::new(RouteConfig::from_annotations(&ann));

        // host-level redirect rules (RedirectRules plugin writes straight to routes)
        for rr in &cfg.redirect_rules {
            routes.insert(
                rr.src_host.clone(),
                RouteEntry {
                    pattern: rr.src_host.clone(),
                    kind: RouteKind::Redirect {
                        status: rr.status,
                        target: rr.target.clone(),
                    },
                    config: cfg.clone(),
                    meta: RouteMeta::default(),
                },
            );
        }

        let Some(spec) = &ing.spec else { continue };
        for rule in spec.rules.iter().flatten() {
            let Some(http) = &rule.http else { continue };
            let host = rule.host.clone().unwrap_or_default().to_ascii_lowercase();

            for p in &http.paths {
                let Some(backend) = &p.backend.service else {
                    continue;
                };

                let mut path = p.path.clone().unwrap_or_default();
                if path.is_empty() {
                    path = "/".to_string();
                }
                if !path.starts_with('/') {
                    path = format!("/{path}");
                }

                let svc_key = format!("{ns}/{}", backend.name);
                let Some(svc) = services.get(&svc_key) else {
                    continue;
                };
                let Some((protocol, port_number)) = backend_config(backend, svc) else {
                    continue;
                };
                if port_number <= 0 {
                    continue;
                }

                let target = build_host_port(ns, &backend.name, port_number);
                let scheme = resolve_scheme(&protocol, &cfg.upstream_protocol);
                let meta = RouteMeta {
                    ingress_namespace: ns.to_string(),
                    ingress_name: ing.metadata.name.clone().unwrap_or_default(),
                    service_name: backend.name.clone(),
                    service_type: svc
                        .spec
                        .as_ref()
                        .and_then(|s| s.type_.clone())
                        .unwrap_or_default(),
                };
                register(
                    &mut routes,
                    &host,
                    &path,
                    &p.path_type,
                    &target,
                    scheme,
                    &cfg,
                    &meta,
                );
            }
        }
    }

    Router::new(routes)
}

/// service `host:servicePort` -> pod `targetPort` (reloadService).
pub fn build_port_routes(services: &[&Service]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for svc in services {
        let ns = svc.metadata.namespace.as_deref().unwrap_or("");
        let name = svc.metadata.name.as_deref().unwrap_or("");
        let Some(spec) = &svc.spec else { continue };
        for sp in spec.ports.iter().flatten() {
            let addr = build_host_port(ns, name, sp.port);
            // Go reads TargetPort.IntVal: a named (string) target port is 0.
            let target = match &sp.target_port {
                Some(IntOrString::Int(i)) => i.to_string(),
                _ => "0".to_string(),
            };
            map.insert(addr, target);
        }
    }
    map
}

/// service `host` -> round-robin pod IPs (reloadEndpoint). Endpoints with no
/// usable address are omitted.
pub fn build_host_routes(endpoints: &[&Endpoints]) -> HashMap<String, Rrlb> {
    let mut map = HashMap::new();
    for ep in endpoints {
        let ns = ep.metadata.namespace.as_deref().unwrap_or("");
        let name = ep.metadata.name.as_deref().unwrap_or("");
        let mut ips = Vec::new();
        for ss in ep.subsets.iter().flatten() {
            for addr in ss.addresses.iter().flatten() {
                ips.push(addr.ip.clone());
            }
        }
        if !ips.is_empty() {
            map.insert(build_host(ns, name), Rrlb::new(ips));
        }
    }
    map
}

fn load_tls_secret(s: &Secret) -> Option<Arc<LoadedCert>> {
    if s.type_.as_deref() != Some("kubernetes.io/tls") {
        return None;
    }
    let data = s.data.as_ref()?;
    let crt = data.get("tls.crt")?.0.clone();
    let key = data.get("tls.key").map(|b| b.0.clone()).unwrap_or_default();
    LoadedCert::from_pem(crt, key).map(Arc::new)
}

/// Collect the TLS certs to serve (reloadSecret). By default only secrets
/// referenced by an ingress `spec.tls.secretName`; with `load_all`, every
/// TLS-typed secret.
pub fn build_certs(
    ingresses: &[&Ingress],
    secrets: &HashMap<String, &Secret>,
    load_all: bool,
) -> Vec<Arc<LoadedCert>> {
    if load_all {
        return secrets
            .values()
            .filter_map(|s| load_tls_secret(s))
            .collect();
    }

    let mut referenced = BTreeSet::new();
    for ing in ingresses {
        let ns = ing.metadata.namespace.as_deref().unwrap_or("");
        if let Some(spec) = &ing.spec {
            for t in spec.tls.iter().flatten() {
                if let Some(sn) = &t.secret_name {
                    referenced.insert(format!("{ns}/{sn}"));
                }
            }
        }
    }

    referenced
        .iter()
        .filter_map(|k| secrets.get(k))
        .filter_map(|s| load_tls_secret(s))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Table as CertTable;
    use crate::router::Match;
    use k8s_openapi::api::core::v1::{
        EndpointAddress, EndpointSubset, Endpoints, Secret, Service, ServicePort, ServiceSpec,
    };
    use k8s_openapi::api::networking::v1::{
        HTTPIngressPath, HTTPIngressRuleValue, Ingress, IngressBackend, IngressRule,
        IngressServiceBackend, IngressSpec, IngressTLS, ServiceBackendPort,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::ByteString;
    use std::collections::BTreeMap;

    const CLASS: &str = "parapet";

    #[test]
    fn resolve_scheme_matches_go_order() {
        use UpstreamProtocol::{Http, Https};
        // appProtocol names a known scheme -> wins regardless of annotation
        assert_eq!(resolve_scheme("h2c", &Http), UpstreamScheme::H2c);
        assert_eq!(resolve_scheme("h2c", &Https), UpstreamScheme::H2c);
        assert_eq!(resolve_scheme("https", &Http), UpstreamScheme::Https);
        // unset appProtocol -> falls back to the upstream-protocol annotation
        assert_eq!(resolve_scheme("", &Http), UpstreamScheme::Http);
        assert_eq!(resolve_scheme("", &Https), UpstreamScheme::Https);
        // any other appProtocol -> plain HTTP, ignoring the annotation
        assert_eq!(resolve_scheme("grpc", &Https), UpstreamScheme::Http);
    }

    fn meta(ns: &str, name: &str) -> ObjectMeta {
        ObjectMeta {
            namespace: Some(ns.into()),
            name: Some(name.into()),
            ..Default::default()
        }
    }

    fn cluster_ip_service(ns: &str, name: &str, port: i32, target_port: i32) -> Service {
        Service {
            metadata: meta(ns, name),
            spec: Some(ServiceSpec {
                type_: Some("ClusterIP".into()),
                ports: Some(vec![ServicePort {
                    port,
                    target_port: Some(IntOrString::Int(target_port)),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn ingress_to_service(
        ns: &str,
        name: &str,
        host: &str,
        path: &str,
        path_type: &str,
        svc_name: &str,
        svc_port: i32,
    ) -> Ingress {
        Ingress {
            metadata: meta(ns, name),
            spec: Some(IngressSpec {
                ingress_class_name: Some(CLASS.into()),
                rules: Some(vec![IngressRule {
                    host: Some(host.into()),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![HTTPIngressPath {
                            path: Some(path.into()),
                            path_type: path_type.into(),
                            backend: IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: svc_name.into(),
                                    port: Some(ServiceBackendPort {
                                        number: Some(svc_port),
                                        ..Default::default()
                                    }),
                                }),
                                ..Default::default()
                            },
                        }],
                    }),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn endpoints(ns: &str, name: &str, ips: &[&str]) -> Endpoints {
        Endpoints {
            metadata: meta(ns, name),
            subsets: Some(vec![EndpointSubset {
                addresses: Some(
                    ips.iter()
                        .map(|ip| EndpointAddress {
                            ip: ip.to_string(),
                            ..Default::default()
                        })
                        .collect(),
                ),
                ..Default::default()
            }]),
        }
    }

    fn svc_map(svcs: &[Service]) -> HashMap<String, &Service> {
        svcs.iter()
            .map(|s| {
                (
                    format!(
                        "{}/{}",
                        s.metadata.namespace.as_deref().unwrap(),
                        s.metadata.name.as_deref().unwrap()
                    ),
                    s,
                )
            })
            .collect()
    }

    fn matched(r: &Router<RouteEntry>, host: &str, path: &str) -> String {
        match r.lookup(host, path) {
            Match::Found(e) => e.pattern.clone(),
            _ => String::new(),
        }
    }

    // --- TestReloadIngress ---

    #[test]
    fn implementation_specific_registers_as_is() {
        let svcs = [cluster_ip_service("default", "web", 80, 8080)];
        let ing = ingress_to_service(
            "default",
            "ing",
            "example.com",
            "/",
            "ImplementationSpecific",
            "web",
            80,
        );
        let r = build_router(&[&ing], &svc_map(&svcs), CLASS);
        assert_eq!(matched(&r, "example.com", "/"), "example.com/");
    }

    #[test]
    fn prefix_registers_exact_and_subtree() {
        let svcs = [cluster_ip_service("default", "web", 80, 8080)];
        let ing = ingress_to_service("default", "ing", "example.com", "/app", "Prefix", "web", 80);
        let r = build_router(&[&ing], &svc_map(&svcs), CLASS);
        assert_eq!(matched(&r, "example.com", "/app"), "example.com/app");
        assert_eq!(matched(&r, "example.com", "/app/sub"), "example.com/app/");
    }

    #[test]
    fn exact_registers_single_path() {
        let svcs = [cluster_ip_service("default", "web", 80, 8080)];
        let ing = ingress_to_service("default", "ing", "example.com", "/app", "Exact", "web", 80);
        let r = build_router(&[&ing], &svc_map(&svcs), CLASS);
        assert_eq!(matched(&r, "example.com", "/app"), "example.com/app");
        assert_eq!(matched(&r, "example.com", "/app/sub"), ""); // must not match subtree
    }

    #[test]
    fn skips_non_matching_class() {
        let svcs = [cluster_ip_service("default", "web", 80, 8080)];
        let mut ing = ingress_to_service(
            "default",
            "ing",
            "example.com",
            "/",
            "ImplementationSpecific",
            "web",
            80,
        );
        ing.spec.as_mut().unwrap().ingress_class_name = Some("not-parapet".into());
        let r = build_router(&[&ing], &svc_map(&svcs), CLASS);
        assert_eq!(matched(&r, "example.com", "/"), "");
    }

    #[test]
    fn skips_path_when_backend_service_missing() {
        let ing = ingress_to_service(
            "default",
            "ing",
            "example.com",
            "/",
            "ImplementationSpecific",
            "web",
            80,
        );
        let r = build_router(&[&ing], &HashMap::new(), CLASS); // no services
        assert_eq!(matched(&r, "example.com", "/"), "");
    }

    // --- TestReloadServiceAndEndpoint ---

    #[test]
    fn service_and_endpoint_resolve_to_pod() {
        let svcs = [cluster_ip_service("default", "web", 80, 8080)];
        let eps = [endpoints("default", "web", &["10.0.0.1"])];

        let table = crate::route::Table::new();
        table.set_port_routes(build_port_routes(&svcs.iter().collect::<Vec<_>>()));
        table.set_host_routes(build_host_routes(&eps.iter().collect::<Vec<_>>()));

        assert_eq!(
            table.lookup("web.default.svc.cluster.local:80").as_deref(),
            Some("10.0.0.1:8080")
        );
        assert_eq!(table.lookup("missing.default.svc.cluster.local:80"), None);
    }

    #[test]
    fn empty_subset_is_not_routed() {
        let svcs = [cluster_ip_service("default", "web", 80, 8080)];
        let ep = Endpoints {
            metadata: meta("default", "web"),
            subsets: None,
        };
        let table = crate::route::Table::new();
        table.set_port_routes(build_port_routes(&svcs.iter().collect::<Vec<_>>()));
        table.set_host_routes(build_host_routes(&[&ep]));
        assert_eq!(table.lookup("web.default.svc.cluster.local:80"), None);
    }

    // --- TestReloadSecret ---

    fn tls_secret(ns: &str, name: &str, crt: &[u8], key: &[u8]) -> Secret {
        let mut data = BTreeMap::new();
        data.insert("tls.crt".to_string(), ByteString(crt.to_vec()));
        data.insert("tls.key".to_string(), ByteString(key.to_vec()));
        Secret {
            metadata: meta(ns, name),
            type_: Some("kubernetes.io/tls".into()),
            data: Some(data),
            ..Default::default()
        }
    }

    fn self_signed(dns: &str) -> (Vec<u8>, Vec<u8>) {
        let ck = rcgen::generate_simple_self_signed(vec![dns.to_string()]).unwrap();
        (
            ck.cert.pem().into_bytes(),
            ck.key_pair.serialize_pem().into_bytes(),
        )
    }

    #[test]
    fn loads_secret_referenced_by_ingress_tls() {
        let (crt, key) = self_signed("secure.example.com");
        let secret = tls_secret("default", "tls", &crt, &key);
        let ing = Ingress {
            metadata: meta("default", "ing"),
            spec: Some(IngressSpec {
                tls: Some(vec![IngressTLS {
                    secret_name: Some("tls".into()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let secrets: HashMap<String, &Secret> =
            [("default/tls".to_string(), &secret)].into_iter().collect();

        let table = CertTable::build(build_certs(&[&ing], &secrets, false));
        assert!(table.get("secure.example.com").is_some());
        assert!(table.get("other.example.com").is_none());
    }

    #[test]
    fn does_not_load_unreferenced_secret_by_default() {
        let (crt, key) = self_signed("secure.example.com");
        let secret = tls_secret("default", "tls", &crt, &key);
        let secrets: HashMap<String, &Secret> =
            [("default/tls".to_string(), &secret)].into_iter().collect();

        let table = CertTable::build(build_certs(&[], &secrets, false));
        assert!(table.get("secure.example.com").is_none());
    }

    #[test]
    fn load_all_certs_loads_unreferenced_secret() {
        let (crt, key) = self_signed("secure.example.com");
        let secret = tls_secret("default", "tls", &crt, &key);
        let secrets: HashMap<String, &Secret> =
            [("default/tls".to_string(), &secret)].into_iter().collect();

        let table = CertTable::build(build_certs(&[], &secrets, true));
        assert!(table.get("secure.example.com").is_some());
    }

    // --- integrated golden gate ---

    #[test]
    fn golden_end_to_end() {
        // ingress -> service -> endpoints, full resolution path
        let svcs = [cluster_ip_service("default", "web", 80, 8080)];
        let eps = [endpoints("default", "web", &["10.0.0.1", "10.0.0.2"])];
        let ing = ingress_to_service("default", "ing", "example.com", "/app", "Prefix", "web", 80);

        let router = build_router(&[&ing], &svc_map(&svcs), CLASS);
        // routing decision
        match router.lookup("example.com", "/app/x") {
            Match::Found(e) => {
                assert_eq!(e.pattern, "example.com/app/");
                assert_eq!(
                    e.kind,
                    RouteKind::Service {
                        target: "web.default.svc.cluster.local:80".into(),
                        scheme: UpstreamScheme::Http,
                    }
                );
            }
            other => panic!("expected Found, got {other:?}"),
        }

        // service target resolves to a concrete pod addr
        let table = crate::route::Table::new();
        table.set_port_routes(build_port_routes(&svcs.iter().collect::<Vec<_>>()));
        table.set_host_routes(build_host_routes(&eps.iter().collect::<Vec<_>>()));
        // 2 pods, pre-increment RR -> first pick is index 1
        assert_eq!(
            table.lookup("web.default.svc.cluster.local:80").as_deref(),
            Some("10.0.0.2:8080")
        );
    }
}
