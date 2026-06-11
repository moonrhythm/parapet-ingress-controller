package edgecp

import (
	"reflect"
	"testing"

	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func pt(t networking.PathType) *networking.PathType { return &t }

func routedIngress(ns, name string, anns map[string]string, rules ...networking.IngressRule) networking.Ingress {
	return networking.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: anns},
		Spec:       networking.IngressSpec{Rules: rules},
	}
}

func httpRule(host string, paths ...networking.HTTPIngressPath) networking.IngressRule {
	return networking.IngressRule{
		Host: host,
		IngressRuleValue: networking.IngressRuleValue{
			HTTP: &networking.HTTPIngressRuleValue{Paths: paths},
		},
	}
}

func TestBuildZoneRoutes(t *testing.T) {
	ings := []networking.Ingress{
		// Prefix registers both "host/path" and "host/path/" (controller parity);
		// host is lowercased.
		routedIngress("cust1", "api", map[string]string{WAFZoneAnnotation: "z"},
			httpRule("ACME.com",
				networking.HTTPIngressPath{Path: "/api", PathType: pt(networking.PathTypePrefix)})),
		// Prefix at root registers only "host/".
		routedIngress("cust1", "root", map[string]string{WAFZoneAnnotation: "z"},
			httpRule("root.acme.com",
				networking.HTTPIngressPath{Path: "/", PathType: pt(networking.PathTypePrefix)})),
		// Exact strips the trailing slash; exact root falls back to prefix
		// (matching the controller's warning path).
		routedIngress("cust2", "exact", map[string]string{WAFZoneAnnotation: "cust9/zz"},
			httpRule("ex.acme.com",
				networking.HTTPIngressPath{Path: "/login/", PathType: pt(networking.PathTypeExact)},
				networking.HTTPIngressPath{Path: "/", PathType: pt(networking.PathTypeExact)})),
		// ImplementationSpecific (and nil PathType) registers as-is; empty path
		// becomes "/", missing leading slash is added.
		routedIngress("cust3", "impl", map[string]string{WAFZoneAnnotation: "z"},
			httpRule("impl.acme.com",
				networking.HTTPIngressPath{Path: "raw"},
				networking.HTTPIngressPath{Path: ""})),
		// Host-less rule and HTTP-less rule contribute nothing.
		routedIngress("cust4", "skip", map[string]string{WAFZoneAnnotation: "z"},
			httpRule("", networking.HTTPIngressPath{Path: "/x", PathType: pt(networking.PathTypePrefix)}),
			networking.IngressRule{Host: "nohttp.acme.com"}),
		// No annotation contributes nothing.
		routedIngress("cust5", "plain", nil,
			httpRule("plain.acme.com", networking.HTTPIngressPath{Path: "/", PathType: pt(networking.PathTypePrefix)})),
	}

	got := buildZoneRoutes(ings, WAFZoneAnnotation, false)
	want := map[string]string{
		"acme.com/api":      "cust1/z",
		"acme.com/api/":     "cust1/z",
		"root.acme.com/":    "cust1/z",
		"ex.acme.com/login": "cust9/zz", // cross-ns ref allowed for the WAF
		"ex.acme.com/":      "cust9/zz",
		"impl.acme.com/raw": "cust3/z",
		"impl.acme.com/":    "cust3/z",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestBuildZoneRoutesSameNamespaceOnly(t *testing.T) {
	ings := []networking.Ingress{
		routedIngress("cust1", "own", map[string]string{RateLimitZoneAnnotation: "basic"},
			httpRule("a.acme.com", networking.HTTPIngressPath{Path: "/", PathType: pt(networking.PathTypePrefix)})),
		// Cross-namespace rate-limit zone references are ignored (shared
		// counter state — same posture as buildRateLimitHostZone).
		routedIngress("cust2", "steal", map[string]string{RateLimitZoneAnnotation: "cust1/basic"},
			httpRule("b.acme.com", networking.HTTPIngressPath{Path: "/", PathType: pt(networking.PathTypePrefix)})),
	}
	got := buildZoneRoutes(ings, RateLimitZoneAnnotation, true)
	want := map[string]string{"a.acme.com/": "cust1/basic"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
