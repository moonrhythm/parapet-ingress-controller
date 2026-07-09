package wsh2

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsExtendedConnect(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		method   string
		protocol string
		want     bool
	}{
		{"extended connect websocket", http.MethodConnect, "websocket", true},
		{"extended connect other proto", http.MethodConnect, "foo", true},
		{"plain connect", http.MethodConnect, "", false},
		{"get with protocol", http.MethodGet, "websocket", false},
		{"plain get", http.MethodGet, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/", nil)
			if tc.protocol != "" {
				r.Header.Set(":protocol", tc.protocol)
			}
			assert.Equal(t, tc.want, IsExtendedConnect(r))
		})
	}
}

func TestNormalize(t *testing.T) {
	t.Parallel()

	body := io.NopCloser(strings.NewReader("client-frames"))
	r := httptest.NewRequest(http.MethodConnect, "/chat?room=1", body)
	r.Header.Set(":protocol", "websocket")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Sec-WebSocket-Protocol", "chat")
	r.Header.Set("Accept-Encoding", "gzip")
	r.Header.Set("Content-Length", "13")
	r.Header.Set("Transfer-Encoding", "chunked")
	r.Header.Set("Expect", "100-continue")
	r.ContentLength = -1

	out := Normalize(r)

	assert.Equal(t, http.MethodGet, out.Method, "method rewritten to GET")
	assert.Equal(t, "Upgrade", out.Header.Get("Connection"))
	assert.Equal(t, "websocket", out.Header.Get("Upgrade"))
	assert.Empty(t, out.Header.Get(":protocol"), ":protocol deleted")
	assert.Empty(t, out.Header.Get("Accept-Encoding"), "Accept-Encoding deleted")
	assert.Empty(t, out.Header.Get("Content-Length"), "Content-Length deleted")
	assert.Empty(t, out.Header.Get("Transfer-Encoding"), "Transfer-Encoding deleted")
	assert.Empty(t, out.Header.Get("Expect"), "Expect deleted")
	assert.Equal(t, "13", out.Header.Get("Sec-WebSocket-Version"), "ws headers ride through")
	assert.Equal(t, "chat", out.Header.Get("Sec-WebSocket-Protocol"))

	// stream detached: body is empty, ContentLength 0.
	assert.Equal(t, http.NoBody, out.Body)
	assert.Zero(t, out.ContentLength)

	// the original stream is parked in the context and readable.
	stream, ok := TunnelStream(out.Context())
	require.True(t, ok)
	got, err := io.ReadAll(stream)
	require.NoError(t, err)
	assert.Equal(t, "client-frames", string(got))
}

func TestNormalizeNilBody(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodConnect, "/", nil)
	r.Body = nil
	r.Header.Set(":protocol", "websocket")

	out := Normalize(r)
	stream, ok := TunnelStream(out.Context())
	require.True(t, ok)
	assert.Equal(t, http.NoBody, stream, "nil body parks as http.NoBody, never nil")
}

func TestTunnelStreamAbsent(t *testing.T) {
	t.Parallel()

	_, ok := TunnelStream(context.Background())
	assert.False(t, ok)
}

// TestAcceptKeyVector pins the RFC 6455 §1.3 worked example.
func TestAcceptKeyVector(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", AcceptKey("dGhlIHNhbXBsZSBub25jZQ=="))
}

func TestGenerateKeyAndCheckAccept(t *testing.T) {
	t.Parallel()

	k1 := GenerateKey()
	k2 := GenerateKey()
	assert.NotEqual(t, k1, k2, "keys are random")

	raw, err := base64.StdEncoding.DecodeString(k1)
	require.NoError(t, err)
	assert.Len(t, raw, 16, "16 random bytes per RFC 6455 §4.1")

	assert.True(t, CheckAccept(AcceptKey(k1), k1))
	assert.False(t, CheckAccept(AcceptKey(k1), k2), "accept for a different key is rejected")
	assert.False(t, CheckAccept("", k1))
}
