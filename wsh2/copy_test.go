package wsh2

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopy(t *testing.T) {
	t.Parallel()

	var dst bytes.Buffer
	var flushes int
	err := Copy(&dst, strings.NewReader("hello world"), func() { flushes++ })
	require.NoError(t, err)
	assert.Equal(t, "hello world", dst.String())
	assert.Positive(t, flushes, "flush called at least once")
}

func TestCopyNilFlush(t *testing.T) {
	t.Parallel()

	var dst bytes.Buffer
	err := Copy(&dst, strings.NewReader("data"), nil)
	require.NoError(t, err)
	assert.Equal(t, "data", dst.String())
}

type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }

func TestCopyWriteError(t *testing.T) {
	t.Parallel()

	want := assert.AnError
	err := Copy(errWriter{err: want}, strings.NewReader("x"), nil)
	assert.ErrorIs(t, err, want)
}
