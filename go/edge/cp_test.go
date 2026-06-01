package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCpClient_FetchCert200ParsesBodyAndEtagAndSendsBearer(t *testing.T) {
	var gotAuth, gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotQuery = r.URL.Query().Get("sni")
		w.Header().Set("ETag", `"abc"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"chain_pem":"CHAIN","key_pem":"KEY"}`))
	}))
	defer srv.Close()

	cp, err := NewCpClient(srv.URL, "tok-123", nil)
	require.NoError(t, err)
	res, err := cp.FetchCert("acme.com", "")
	require.NoError(t, err)
	assert.False(t, res.Unchanged)
	assert.Equal(t, "CHAIN", string(res.ChainPEM))
	assert.Equal(t, "KEY", string(res.KeyPEM))
	assert.Equal(t, `"abc"`, res.Etag)
	assert.Equal(t, "Bearer tok-123", gotAuth)
	assert.Equal(t, "/v1/certs", gotPath)
	assert.Equal(t, "acme.com", gotQuery)
}

func TestCpClient_FetchCertWildcardSNIEncoded(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("sni")
		_, _ = w.Write([]byte(`{"chain_pem":"C","key_pem":"K"}`))
	}))
	defer srv.Close()
	cp, _ := NewCpClient(srv.URL, "t", nil)
	_, err := cp.FetchCert("*.acme.com", "")
	require.NoError(t, err)
	assert.Equal(t, "*.acme.com", gotQuery, "wildcard SNI round-trips via percent-encoding")
}

func TestCpClient_FetchCert304IsUnchangedAndSendsIfNoneMatch(t *testing.T) {
	var gotINM string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotINM = r.Header.Get("If-None-Match")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	cp, _ := NewCpClient(srv.URL, "t", nil)
	res, err := cp.FetchCert("acme.com", `"v1"`)
	require.NoError(t, err)
	assert.True(t, res.Unchanged)
	assert.Equal(t, `"v1"`, gotINM)
}

func TestCpClient_FetchCertNon200IsError(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		cp, _ := NewCpClient(srv.URL, "t", nil)
		_, err := cp.FetchCert("evil.com", "")
		assert.Error(t, err, "status %d is fail-static error", code)
		srv.Close()
	}
}

func TestCpClient_FetchWaf200ParsesPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/waf", r.URL.Path)
		w.Header().Set("ETag", `"w1"`)
		_, _ = w.Write([]byte(`{"generation":7,"global_rules":"G","zones":{"ns/z":"ZY"},"host_zone_map":{"acme.com":"ns/z"}}`))
	}))
	defer srv.Close()
	cp, _ := NewCpClient(srv.URL, "t", nil)
	res, err := cp.FetchWaf("")
	require.NoError(t, err)
	assert.False(t, res.Unchanged)
	assert.EqualValues(t, 7, res.Generation)
	assert.Equal(t, "G", res.GlobalRules)
	assert.Equal(t, "ZY", res.Zones["ns/z"])
	assert.Equal(t, "ns/z", res.HostZoneMap["acme.com"])
	assert.Equal(t, `"w1"`, res.Etag)
}

func TestCpClient_FetchWaf304(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, `"w1"`, r.Header.Get("If-None-Match"))
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	cp, _ := NewCpClient(srv.URL, "t", nil)
	res, err := cp.FetchWaf(`"w1"`)
	require.NoError(t, err)
	assert.True(t, res.Unchanged)
}
