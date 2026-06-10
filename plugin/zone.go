package plugin

import "strings"

// ZoneKey resolves a zone-reference annotation value (waf-zone,
// ratelimit-zone) to a zone registry key (<namespace>/<name>). A bare id uses
// the ingress's namespace; "ns/id" is used verbatim. Returns ok=false for an
// empty or malformed value.
func ZoneKey(ingressNamespace, annotation string) (key string, ok bool) {
	v := strings.TrimSpace(annotation)
	if v == "" {
		return "", false
	}
	if i := strings.IndexByte(v, '/'); i >= 0 {
		ns := strings.TrimSpace(v[:i])
		name := strings.TrimSpace(v[i+1:])
		if ns == "" || name == "" || strings.Contains(name, "/") {
			return "", false
		}
		return ns + "/" + name, true
	}
	return ingressNamespace + "/" + v, true
}
