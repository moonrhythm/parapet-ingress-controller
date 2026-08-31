package methodlabel

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOf(t *testing.T) {
	t.Parallel()

	registered := []string{
		http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect,
		http.MethodOptions, http.MethodTrace, Query,
	}
	for _, m := range registered {
		assert.Equal(t, m, Of(m), m)
	}

	assert.Equal(t, Other, Of(""))
	assert.Equal(t, Other, Of("get"))
	assert.Equal(t, Other, Of("FOOBAR"))
	assert.Equal(t, Other, Of("PROPFIND"), "WebDAV stays Other")
	assert.Equal(t, Other, Of("SEARCH"), "WebDAV SEARCH stays Other")
}
