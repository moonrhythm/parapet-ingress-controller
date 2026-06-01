package edgecp

import (
	"context"
	"log/slog"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/k8s"
)

// Reloader keeps the CertStore in sync with the cluster's TLS Secrets. It does an
// initial list, then watches for changes and re-lists (debounced) — the same
// list-on-change pattern the controller uses, kept simple here since the control
// plane isn't on the request path.
type Reloader struct {
	store     *CertStore
	namespace string
	debounce  time.Duration
}

func NewReloader(store *CertStore, namespace string) *Reloader {
	return &Reloader{store: store, namespace: namespace, debounce: 300 * time.Millisecond}
}

// Start does the initial load and then watches Secrets, reloading on change.
// Blocks until ctx is cancelled; run it in a goroutine.
func (r *Reloader) Start(ctx context.Context) {
	if err := r.reload(ctx); err != nil {
		slog.Error("edgecp: initial secret load failed", "err", err)
	}
	for ctx.Err() == nil {
		w, err := k8s.WatchSecrets(ctx, r.namespace)
		if err != nil {
			slog.Error("edgecp: watch secrets failed; retrying", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		r.drain(ctx, w.ResultChan())
		w.Stop()
	}
}

// drain coalesces a burst of watch events (debounced), then reloads once. Returns
// when the watch channel closes (so Start re-establishes it) or ctx is done.
func (r *Reloader) drain(ctx context.Context, ch <-chan watch.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ch:
			if !ok {
				return
			}
			timer := time.NewTimer(r.debounce)
		coalesce:
			for {
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case _, ok := <-ch:
					if !ok {
						timer.Stop()
						break coalesce
					}
					if !timer.Stop() {
						<-timer.C
					}
					timer.Reset(r.debounce)
				case <-timer.C:
					break coalesce
				}
			}
			if err := r.reload(ctx); err != nil {
				slog.Error("edgecp: secret reload failed", "err", err)
			}
		}
	}
}

// reload lists every kubernetes.io/tls Secret and rebuilds the cert store.
func (r *Reloader) reload(ctx context.Context) error {
	secrets, err := k8s.GetSecrets(ctx, r.namespace)
	if err != nil {
		return err
	}
	var pairs []PEMPair
	for i := range secrets {
		s := &secrets[i]
		if s.Type != v1.SecretTypeTLS {
			continue
		}
		crt := s.Data["tls.crt"]
		key := s.Data["tls.key"]
		if len(crt) == 0 {
			continue
		}
		pairs = append(pairs, PEMPair{ChainPEM: crt, KeyPEM: key})
	}
	r.store.Set(pairs)
	slog.Info("edgecp: cert store reloaded", "tls_secrets", len(pairs))
	return nil
}
