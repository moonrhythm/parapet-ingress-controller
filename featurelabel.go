package controller

import v1 "k8s.io/api/core/v1"

// featureLabelKeys are the mutually-exclusive ConfigMap feature label keys. A
// single ConfigMap must carry at most one of them: every feature reloader
// consumes ALL of a ConfigMap's data values, and the lenient YAML parsers
// cross-parse another feature's documents to zero entries — so a ConfigMap
// labeled for two features would feed each side the other's data. Each reloader
// refuses a ConfigMap carrying any of the OTHER keys (warn-and-skip).
var featureLabelKeys = []string{
	wafLabelKey,
	rateLimitLabelKey,
	corazaLabelKey,
	transformLabelKey,
}

// carriesOtherFeatureLabel reports whether cm carries a feature label other than
// self (the caller's own feature key), returning the first such key. Callers gate
// this on having recognized their own role first, so the fs backend's
// other-feature ConfigMaps (that store holds ConfigMaps the label selector didn't
// filter) fall through silently rather than warn.
func carriesOtherFeatureLabel(cm *v1.ConfigMap, self string) (string, bool) {
	for _, k := range featureLabelKeys {
		if k == self {
			continue
		}
		if _, ok := cm.Labels[k]; ok {
			return k, true
		}
	}
	return "", false
}
