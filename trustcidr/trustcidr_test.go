package trustcidr_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/moonrhythm/parapet-ingress-controller/trustcidr"
)

func reqFrom(ip string) *http.Request {
	return &http.Request{RemoteAddr: ip + ":12345"}
}

func TestParse(t *testing.T) {
	t.Run("true trusts every remote", func(t *testing.T) {
		c := trustcidr.Parse("true")
		require.NotNil(t, c)
		assert.True(t, c(reqFrom("203.0.113.7")))
		assert.True(t, c(reqFrom("10.0.0.1")))
	})

	t.Run("empty and false are nil (distrust)", func(t *testing.T) {
		assert.Nil(t, trustcidr.Parse(""))
		assert.Nil(t, trustcidr.Parse("false"))
	})

	t.Run("named cloudflare group", func(t *testing.T) {
		c := trustcidr.Parse("cloudflare")
		require.NotNil(t, c)
		assert.True(t, c(reqFrom("173.245.48.1")), "inside 173.245.48.0/20")
		assert.False(t, c(reqFrom("203.0.113.7")), "outside cloudflare")
	})

	t.Run("plain CIDR", func(t *testing.T) {
		c := trustcidr.Parse("10.0.0.0/8")
		require.NotNil(t, c)
		assert.True(t, c(reqFrom("10.1.2.3")))
		assert.False(t, c(reqFrom("11.0.0.1")))
	})

	t.Run("mixed groups, CIDRs, whitespace, and empty entries", func(t *testing.T) {
		c := trustcidr.Parse(" cloudflare , 10.0.0.0/8 , , 192.168.1.1/32 ")
		require.NotNil(t, c)
		assert.True(t, c(reqFrom("173.245.48.9")), "cloudflare group")
		assert.True(t, c(reqFrom("10.9.9.9")), "10.0.0.0/8")
		assert.True(t, c(reqFrom("192.168.1.1")), "/32 host")
		assert.False(t, c(reqFrom("203.0.113.7")), "no list entry")
	})

	t.Run("a malformed CIDR token fails fast (panics at startup)", func(t *testing.T) {
		// A non-group token that isn't a valid CIDR is passed to parapet.TrustCIDRs,
		// which panics — surfacing a TRUST_PROXY typo loudly at boot rather than
		// silently trusting nothing. Mirrors the controller (same parse path).
		assert.Panics(t, func() { trustcidr.Parse("not-a-cidr") })
	})
}

func TestPredefinedGroupsPopulated(t *testing.T) {
	for _, k := range []string{"cloudflare", "google", "bunny"} {
		assert.NotEmpty(t, trustcidr.Predefined[k], "group %q must be populated", k)
	}
}
