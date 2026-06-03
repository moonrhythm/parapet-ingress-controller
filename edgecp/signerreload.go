package edgecp

import (
	"context"
	"log/slog"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/k8s"
)

// SignerReloader keeps the serving CP's active Signer in sync with the edge CA
// Secret. It reads the CA via the namespace-wide list the CP already watches (no
// extra `get` grant), rebuilds a Signer on every CA-Secret change, and SetSigner's
// it — so a rotation Job's OLD++NEW write propagates to every replica without a
// restart. Unlike the cert Reloader it is FILTERED to the CA Secret by name, and it
// gates SetSigner on a ca_id change so an unrelated re-list never churns the
// generation.
//
// Active-key selection is annotation-driven: caActiveAnnotation "old" (or absent) ⇒
// tls.key signs and the OLD (first) cert is the active cert; "new" ⇒ tls-new.key
// signs and the NEW (last) cert is active. The active cert is fingerprint-pinned so
// a contradictory annotation/key combination fails closed (keep last-good) rather
// than signing under the wrong cert. RotateCA only ever writes "old"; the "new"
// branch is implemented now so the later active flip is not where it first runs.
type SignerReloader struct {
	server    *Server
	namespace string
	caSecret  string
	ttl, skew time.Duration
	debounce  time.Duration

	// list reads Secrets in namespace; defaults to k8s.GetSecrets (a test seam).
	list func(ctx context.Context, namespace string) ([]v1.Secret, error)
}

func NewSignerReloader(server *Server, namespace, caSecret string, ttl, skew time.Duration) *SignerReloader {
	return &SignerReloader{
		server:    server,
		namespace: namespace,
		caSecret:  caSecret,
		ttl:       ttl,
		skew:      skew,
		debounce:  300 * time.Millisecond,
		list:      k8s.GetSecrets,
	}
}

// LoadOnce does a single synchronous reload (the initial install). It never errors
// on an absent/empty CA — that just leaves the signer unloaded (readiness 503s)
// until the bootstrap Job lands.
func (r *SignerReloader) LoadOnce(ctx context.Context) error { return r.reload(ctx) }

// Watch re-establishes a Secret watch and reloads (debounced) on every event that
// touches the CA Secret. Blocks until ctx is cancelled; run it in a goroutine.
func (r *SignerReloader) Watch(ctx context.Context) {
	for ctx.Err() == nil {
		w, err := k8s.WatchSecrets(ctx, r.namespace)
		if err != nil {
			slog.Error("edgecp: signer watch secrets failed; retrying", "err", err)
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

// isCASecret reports whether a watch event concerns the CA Secret by name (so
// unrelated tenant-cert events never trigger a signer rebuild).
func (r *SignerReloader) isCASecret(ev watch.Event) bool {
	s, ok := ev.Object.(*v1.Secret)
	return ok && s.Name == r.caSecret
}

// drain coalesces a burst of CA-Secret events (debounced), ignoring events for any
// other Secret, then reloads once. Returns when the channel closes or ctx is done.
func (r *SignerReloader) drain(ctx context.Context, ch <-chan watch.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if !r.isCASecret(ev) {
				continue
			}
			timer := time.NewTimer(r.debounce)
		coalesce:
			for {
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case ev2, ok := <-ch:
					if !ok {
						timer.Stop()
						break coalesce
					}
					if !r.isCASecret(ev2) {
						continue // ignore noise; keep counting down
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
				slog.Error("edgecp: signer reload failed", "err", err)
			}
		}
	}
}

// reload lists Secrets, finds the CA Secret, builds a candidate Signer for the
// annotation-selected active key, and SetSigner's it only when the ca_id changes.
// Any failure (CA absent, empty key field, contradictory annotation, malformed
// bundle) logs and KEEPS the last-good signer rather than dropping issuance.
func (r *SignerReloader) reload(ctx context.Context) error {
	secs, err := r.list(ctx, r.namespace)
	if err != nil {
		return err
	}
	var sec *v1.Secret
	for i := range secs {
		if secs[i].Name == r.caSecret {
			sec = &secs[i]
			break
		}
	}
	if sec == nil {
		slog.Warn("edgecp: edge CA secret not found yet", "secret", r.namespace+"/"+r.caSecret)
		return nil
	}
	crt := sec.Data["tls.crt"]
	if len(crt) == 0 {
		slog.Warn("edgecp: edge CA secret has no tls.crt yet", "secret", r.namespace+"/"+r.caSecret)
		return nil
	}

	// Select the active key field AND the active cert fingerprint as a coherent unit
	// from the tls-active annotation. OLD is the first cert, NEW the last.
	active := sec.Annotations[caActiveAnnotation]
	fps := certBundleFPs(crt)
	var keyPEM []byte
	var activeFP string
	switch active {
	case caActiveNew:
		keyPEM = sec.Data[caNewKeyField]
		if len(fps) > 0 {
			activeFP = fps[len(fps)-1]
		}
	default: // "old" or absent
		keyPEM = sec.Data["tls.key"]
		if len(fps) > 0 {
			activeFP = fps[0]
		}
	}
	if len(keyPEM) == 0 {
		slog.Warn("edgecp: edge CA active key field empty; keeping last-good", "active", active, "secret", r.namespace+"/"+r.caSecret)
		return nil
	}

	cand, warnings, err := NewProvidedSignerActive(crt, keyPEM, activeFP, r.ttl, r.skew)
	if err != nil {
		slog.Error("edgecp: build edge CA signer; keeping last-good", "err", err, "active", active)
		return nil
	}
	for _, msg := range warnings {
		slog.Warn("edge CA: " + msg)
	}
	if cand.CAID() == r.server.CurrentCAID() {
		return nil // unchanged bundle; do not churn the generation
	}
	r.server.SetSigner(cand)
	if active == "" {
		active = caActiveOld
	}
	slog.Info("edgecp: edge CA signer installed",
		"ca_id", cand.CAID(), "active", active, "certs", len(fps), "secret", r.namespace+"/"+r.caSecret)
	return nil
}
