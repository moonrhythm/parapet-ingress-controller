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
	// skipSecret, if set, is the edge CA Secret's name: never load it as a tenant
	// serving cert. The CA Secret is Opaque so the type filter already excludes it;
	// this makes the SignerReloader its sole consumer (belt-and-suspenders).
	skipSecret string
	debounce   time.Duration
}

func NewReloader(store *CertStore, namespace, skipSecret string) *Reloader {
	return &Reloader{store: store, namespace: namespace, skipSecret: skipSecret, debounce: 300 * time.Millisecond}
}

// Start watches Secrets, relisting on every (re)connect and on change.
// Blocks until ctx is cancelled; run it in a goroutine.
func (r *Reloader) Start(ctx context.Context) {
	watchAndRelist(ctx, "secrets",
		func(ctx context.Context) (watch.Interface, error) { return k8s.WatchSecrets(ctx, r.namespace) },
		r.reload, r.drain)
}

// watchAndRelist is the relist-on-(re)connect watch loop every edgecp reloader
// shares. On each iteration it (re)establishes the watch, RELISTS once via
// reload, then drains events (each triggers a debounced reload) until the watch
// closes — then reconnects.
//
// The relist is the fix for a silent-staleness bug: the bare k8s Watch carries
// no resourceVersion and never replays history, so a change that lands in the
// gap between one watch closing and the next opening is never delivered. Because
// every reload is a full rebuild triggered only by a watch event, that missed
// change would otherwise persist until some unrelated later event — or a process
// restart (the "edge keeps stale config until restart" incident). Relisting once
// the watch is live closes the gap: anything that changed while no watch was
// established is captured by the list, and any change from this point on is
// delivered as an event on w. This mirrors the controller's resyncStore
// (controller.go), but is simpler here because each reload already rebuilds the
// whole store, so events only need to act as a trigger — not be replayed in
// order. Establishing the watch BEFORE the relist (rather than after, as the
// controller does) leaves no residual gap: a change racing the relist still
// delivers an event on the now-live watch.
//
// Every edgecp store is content-gated (cert version, WAF/ratelimit recompute,
// the signer's ca_id/active-fp tuple), so a no-change relist is a true no-op —
// no etag bump and no /v1/events wake of the edge fleet.
//
// drain blocks until the watch channel closes (so the loop reconnects) or ctx is
// done; label names the resource in logs.
func watchAndRelist(
	ctx context.Context,
	label string,
	watchFn func(ctx context.Context) (watch.Interface, error),
	reload func(ctx context.Context) error,
	drain func(ctx context.Context, ch <-chan watch.Event),
) {
	for ctx.Err() == nil {
		w, err := watchFn(ctx)
		if err != nil {
			slog.Error("edgecp: watch "+label+" failed; retrying", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		if err := reload(ctx); err != nil {
			slog.Error("edgecp: "+label+" relist on watch (re)connect failed; keeping last-good", "err", err)
		}
		drain(ctx, w.ResultChan())
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
		if r.skipSecret != "" && s.Name == r.skipSecret {
			continue // the edge CA Secret is owned by the SignerReloader, not a tenant cert
		}
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
