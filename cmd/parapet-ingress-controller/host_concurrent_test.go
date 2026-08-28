package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostRateLimit_UnknownHostsShareOther(t *testing.T) {
	t.Setenv("HOST_CONCURRENT_CAPACITY", "1")
	t.Setenv("HOST_CONCURRENT_SIZE", "0")
	m := hostRateLimit(func(h string) bool { return h == "a.example.com" })
	require.NotNil(t, m)

	started := make(chan struct{})
	block := make(chan struct{})
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-block
		w.WriteHeader(http.StatusOK)
	})
	h := m.ServeHandler(inner)

	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = "x.example.com"
		h.ServeHTTP(rec, r)
		done <- rec.Code
	}()
	select {
	case <-started:
	case <-t.Context().Done():
		t.Fatal("held request did not start")
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "y.example.com"
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "two unknown hosts must share the other bucket")

	close(block)
	assert.Equal(t, http.StatusOK, <-done)
}

func TestHostRateLimit_KnownHostIndependentOfOther(t *testing.T) {
	t.Setenv("HOST_CONCURRENT_CAPACITY", "1")
	t.Setenv("HOST_CONCURRENT_SIZE", "0")
	m := hostRateLimit(func(h string) bool { return h == "a.example.com" })
	require.NotNil(t, m)

	started := make(chan struct{})
	block := make(chan struct{})
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "x.example.com" {
			close(started)
			<-block
		}
		w.WriteHeader(http.StatusOK)
	})
	h := m.ServeHandler(inner)

	done := make(chan struct{})
	go func() {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = "x.example.com"
		h.ServeHTTP(rec, r)
		close(done)
	}()
	select {
	case <-started:
	case <-t.Context().Done():
		t.Fatal("held request did not start")
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "a.example.com"
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusOK, rec.Code, "known host must not share the other bucket")

	close(block)
	<-done
}

func TestHostCountryRateLimit_UnknownHostsShareOther(t *testing.T) {
	t.Setenv("HOST_COUNTRY_CONCURRENT_CAPACITY", "1")
	t.Setenv("HOST_COUNTRY_CONCURRENT_SIZE", "0")
	t.Setenv("HOST_COUNTRY_HEADER", "Cf-Ipcountry")
	m := hostCountryRateLimit(func(h string) bool { return h == "a.example.com" })
	require.NotNil(t, m)

	started := make(chan struct{})
	block := make(chan struct{})
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-block
		w.WriteHeader(http.StatusOK)
	})
	h := m.ServeHandler(inner)

	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = "x.example.com"
		r.Header.Set("Cf-Ipcountry", "US")
		h.ServeHTTP(rec, r)
		done <- rec.Code
	}()
	select {
	case <-started:
	case <-t.Context().Done():
		t.Fatal("held request did not start")
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "y.example.com"
	r.Header.Set("Cf-Ipcountry", "US")
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	close(block)
	assert.Equal(t, http.StatusOK, <-done)
}
