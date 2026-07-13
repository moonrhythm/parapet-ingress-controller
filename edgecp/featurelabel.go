package edgecp

// featureLabelKeys are the mutually-exclusive ConfigMap feature label keys the
// control plane distributes. A single ConfigMap must carry at most one: every
// reloader consumes ALL of a ConfigMap's data values, and the edge's lenient YAML
// parsers cross-parse another feature's documents to zero entries — so a ConfigMap
// labeled for two features would feed each edge store the other's data. Each
// reloader refuses a ConfigMap carrying any of the OTHER keys (warn-and-skip).
var featureLabelKeys = []string{
	WAFLabelKey,
	RateLimitLabelKey,
	CorazaLabelKey,
	CacheLabelKey,
}

// carriesOtherFeatureLabel reports whether labels carry a feature label other
// than self (the caller's own feature key), returning the first such key. Callers
// gate this on having recognized their own role first.
func carriesOtherFeatureLabel(labels map[string]string, self string) (string, bool) {
	for _, k := range featureLabelKeys {
		if k == self {
			continue
		}
		if _, ok := labels[k]; ok {
			return k, true
		}
	}
	return "", false
}
