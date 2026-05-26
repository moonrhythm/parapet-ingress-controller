use std::collections::HashMap;
use std::sync::RwLock;

use super::badaddr::BadAddrs;
use super::rrlb::Rrlb;

/// Resolves a service DNS `host:port` to a concrete pod `ip:port`.
/// Port of `route/table.go`.
///
/// - `host_routes`: `service.ns.svc.cluster.local` -> round-robin pod IPs
/// - `port_routes`: `service.ns.svc.cluster.local:servicePort` -> pod targetPort
#[derive(Default)]
pub struct Table {
    host_routes: RwLock<HashMap<String, Rrlb>>,
    port_routes: RwLock<HashMap<String, String>>,
    bad: BadAddrs,
}

impl Table {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve a `host:port` service address to a `podIP:targetPort`, or `None`.
    pub fn lookup(&self, addr: &str) -> Option<String> {
        // addr is a DNS name of the form service.ns.svc.cluster.local:port
        let i = addr.rfind(':')?; // invalid format -> None
        let host = &addr[..i];

        let target_port = {
            let ports = self.port_routes.read().unwrap();
            ports.get(addr)?.clone()
        };

        let hosts = self.host_routes.read().unwrap();
        let ip = hosts.get(host)?.get(Some(&self.bad))?;
        Some(format!("{ip}:{target_port}"))
    }

    pub fn set_host_routes(&self, routes: HashMap<String, Rrlb>) {
        *self.host_routes.write().unwrap() = routes;
    }

    pub fn set_host_route(&self, host: &str, lb: Option<Rrlb>) {
        let mut hosts = self.host_routes.write().unwrap();
        match lb {
            Some(lb) => {
                hosts.insert(host.to_string(), lb);
            }
            None => {
                hosts.remove(host);
            }
        }
    }

    pub fn set_port_routes(&self, routes: HashMap<String, String>) {
        *self.port_routes.write().unwrap() = routes;
    }

    pub fn mark_bad(&self, addr: &str) {
        self.bad.mark_bad(addr);
    }

    /// Drop bad-address entries whose 2s window has expired. The `bad` map lives
    /// for the process lifetime (it is not rebuilt on reload like the route maps),
    /// so without this it would accumulate one entry per distinct failed pod IP
    /// forever — and pod IPs churn on every deploy. Called from the reload path,
    /// which is also when pod IPs turn over.
    pub fn prune_bad(&self) {
        self.bad.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Table {
        let tb = Table::new();
        let mut hosts = HashMap::new();
        hosts.insert(
            "api.default.svc.cluster.local".to_string(),
            Rrlb::new(vec!["192.168.0.1".into()]),
        );
        hosts.insert(
            "backoffice.default.svc.cluster.local".to_string(),
            Rrlb::new(vec!["192.168.0.2".into()]),
        );
        hosts.insert(
            "api.service.svc.cluster.local".to_string(),
            Rrlb::new(vec!["192.168.1.1".into(), "192.168.1.2".into()]),
        );
        hosts.insert(
            "payment.service.svc.cluster.local".to_string(),
            Rrlb::new(vec!["192.168.2.1".into(), "192.168.2.2".into()]),
        );
        tb.set_host_routes(hosts);

        let mut ports = HashMap::new();
        ports.insert("api.default.svc.cluster.local:8080".into(), "9000".into());
        ports.insert("api.service.svc.cluster.local:8000".into(), "9001".into());
        ports.insert(
            "payment.service.svc.cluster.local:8000".into(),
            "9002".into(),
        );
        ports.insert("about.service.svc.cluster.local:8000".into(), "9003".into());
        tb.set_port_routes(ports);
        tb
    }

    #[test]
    fn not_found() {
        assert_eq!(
            fixture().lookup("frontend.default.svc.cluster.local:8080"),
            None
        );
    }

    #[test]
    fn invalid_format() {
        assert_eq!(fixture().lookup("api.default.svc.cluster.local"), None);
    }

    #[test]
    fn found_host_and_port() {
        assert_eq!(
            fixture()
                .lookup("api.default.svc.cluster.local:8080")
                .as_deref(),
            Some("192.168.0.1:9000")
        );
    }

    #[test]
    fn found_only_host() {
        // never happens in practice (k8s requires a port name) but must not match
        assert_eq!(
            fixture().lookup("backoffice.default.svc.cluster.local:8080"),
            None
        );
    }

    #[test]
    fn some_bad() {
        let tb = fixture();
        tb.mark_bad("192.168.1.1");
        for _ in 0..3 {
            assert_eq!(
                tb.lookup("api.service.svc.cluster.local:8000").as_deref(),
                Some("192.168.1.2:9001")
            );
        }
    }

    #[test]
    fn set_host_route() {
        let tb = fixture();
        tb.set_host_route(
            "about.service.svc.cluster.local",
            Some(Rrlb::new(vec!["192.168.3.1".into()])),
        );
        assert_eq!(
            tb.lookup("about.service.svc.cluster.local:8000").as_deref(),
            Some("192.168.3.1:9003")
        );

        tb.set_host_route(
            "about.service.svc.cluster.local",
            Some(Rrlb::new(vec!["192.168.3.2".into()])),
        );
        assert_eq!(
            tb.lookup("about.service.svc.cluster.local:8000").as_deref(),
            Some("192.168.3.2:9003")
        );
    }
}
