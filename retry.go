package adcore

import (
	"context"
	"math/rand/v2"
	"time"
)

// RetryConfig is values, not code. It governs re-attempts, and applies only to
// errors classified transient — see Kind.Retryable for why that set is as
// narrow as it is.
type RetryConfig struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Jitter         float64 // fraction of the backoff, 0..1
}

// WithDefaults fills the zero-value fields.
func (r RetryConfig) WithDefaults() RetryConfig {
	if r.MaxAttempts <= 0 {
		r.MaxAttempts = 4
	}
	if r.InitialBackoff <= 0 {
		r.InitialBackoff = 250 * time.Millisecond
	}
	if r.MaxBackoff <= 0 {
		r.MaxBackoff = 5 * time.Second
	}
	if r.Jitter < 0 || r.Jitter > 1 {
		r.Jitter = 0.2
	}
	return r
}

// Backoff sleeps for the attempt's exponential delay, jittered, and honours
// cancellation. attempt is 1-based.
//
// A cancelled context yields KindTransport, never KindTransient: the caller
// gave up, and a Kind that invites a re-issue would turn that into one.
func Backoff(ctx context.Context, cfg RetryConfig, attempt int) error {
	d := cfg.InitialBackoff << (attempt - 1)
	// The shift overflows into a negative duration well before attempt 64,
	// and a negative timer fires immediately — which would turn the cap into
	// a busy loop rather than a delay.
	if d > cfg.MaxBackoff || d <= 0 {
		d = cfg.MaxBackoff
	}
	if cfg.Jitter > 0 {
		spread := float64(d) * cfg.Jitter
		d = time.Duration(float64(d) - spread + rand.Float64()*2*spread)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return &Error{Kind: KindTransport, Err: ctx.Err()}
	case <-t.C:
		return nil
	}
}
