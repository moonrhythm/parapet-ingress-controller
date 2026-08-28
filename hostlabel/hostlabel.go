// Package hostlabel collapses a request Host to a bounded label/bucket.
// Hosts the router (or edge known-host oracle) does not serve share Other,
// so a random-Host flood cannot grow maps or metric series.
package hostlabel

// Other is the sentinel for a Host nothing in this process serves.
const Other = "other"

// Of returns host when isKnown is nil or reports true, otherwise Other.
func Of(host string, isKnown func(string) bool) string {
	if isKnown == nil || isKnown(host) {
		return host
	}
	return Other
}
