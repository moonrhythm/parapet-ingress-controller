package corazawaf

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generatedCRSConf is a representative managed-rules SecLang document exactly
// as a platform deployer generates it from typed knobs (paranoia level, anomaly
// threshold, excluded CRS rule ids): explicit engine directives instead of
// @coraza.conf-recommended, the two CRS include forms that the embedded
// coreruleset.FS actually resolves, and id-level exclusions after the includes
// (SecRuleRemoveById removes already-loaded rules).
const generatedCRSConf = `
SecRuleEngine On
SecRequestBodyAccess On
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=1"
SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=5"
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleRemoveById 942100
`

// TestCRSIncludesCompile is the compile gate: the embedded OWASP CRS must be
// loadable through the include forms the docs prescribe. SetDirectives failures
// are controller-log-only in production and last-good for a brand-new zone is
// pass-through, so a non-compiling generated document would be a silent no-op —
// this test makes "the engine accepts the generated CRS document" a CI
// invariant.
func TestCRSIncludesCompile(t *testing.T) {
	t.Parallel()
	in := New(Options{RootFS: coreruleset.FS})
	require.NoError(t, in.SetDirectives(generatedCRSConf))
	assert.True(t, in.Loaded())
}

// TestCRSBareIncludeFormsDoNotResolve pins why CORAZA.md prescribes the
// .conf.example / glob forms: coraza's Include is a plain fs.ReadFile that
// globs only when the path contains '*', and the embedded FS holds
// @crs-setup.conf.example (a file) and @owasp_crs/ (a directory) — so the bare
// forms must keep failing loudly rather than silently loading nothing.
func TestCRSBareIncludeFormsDoNotResolve(t *testing.T) {
	t.Parallel()
	in := New(Options{RootFS: coreruleset.FS})
	assert.Error(t, in.SetDirectives("SecRuleEngine On\nInclude @crs-setup\n"))
	assert.Error(t, in.SetDirectives("SecRuleEngine On\nInclude @owasp_crs\n"))
}

// TestCRSBlocksGETXSSAtParanoiaLevel1 is the behavior canary: a GET reflected
// XSS must be denied 403 by CRS anomaly blocking (949110) at paranoia level 1
// with no request body and body inspection off. This is exactly the case the
// unconditional phase-2 evaluation exists for — 949110 and most CRS detections
// are phase 2, so it goes red if an engine/CRS bump reintroduces body-gated
// phase-2 evaluation or changes the include layout.
func TestCRSBlocksGETXSSAtParanoiaLevel1(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var matched []int
	in := New(Options{
		RootFS: coreruleset.FS,
		OnMatch: func(ev MatchEvent) {
			mu.Lock()
			matched = append(matched, ev.RuleID)
			mu.Unlock()
		},
	})
	require.NoError(t, in.SetDirectives(generatedCRSConf))

	// Browser-shaped headers so the canary exercises the attack signature, not
	// CRS's missing-header hygiene rules.
	newReq := func(target string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) canary")
		r.Header.Set("Accept", "text/html")
		return r
	}

	rec := httptest.NewRecorder()
	in.ServeHandler(okHandler()).ServeHTTP(rec, newReq("/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"))
	assert.Equal(t, http.StatusForbidden, rec.Code, "GET reflected XSS must be denied at PL1")
	mu.Lock()
	assert.Contains(t, matched, 949110, "the block must come from CRS anomaly-score evaluation")
	mu.Unlock()

	rec = httptest.NewRecorder()
	in.ServeHandler(okHandler()).ServeHTTP(rec, newReq("/?q=hello"))
	assert.Equal(t, http.StatusOK, rec.Code, "a clean GET must pass")
}
