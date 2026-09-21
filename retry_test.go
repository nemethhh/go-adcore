package adcore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nemethhh/go-adcore"
)

func TestRetryConfigWithDefaults(t *testing.T) {
	got := adcore.RetryConfig{}.WithDefaults()
	if got.MaxAttempts <= 0 || got.InitialBackoff <= 0 || got.MaxBackoff <= 0 {
		t.Fatalf("WithDefaults left a zero field: %+v", got)
	}
	// An out-of-range jitter is replaced, not clamped to its own bad value.
	if j := (adcore.RetryConfig{Jitter: 7}).WithDefaults().Jitter; j < 0 || j > 1 {
		t.Errorf("Jitter = %v, want a fraction in 0..1", j)
	}
}

func TestRetryConfigWithDefaultsKeepsExplicitValues(t *testing.T) {
	in := adcore.RetryConfig{MaxAttempts: 2, InitialBackoff: time.Second, MaxBackoff: 2 * time.Second, Jitter: 0.5}
	if got := in.WithDefaults(); got != in {
		t.Errorf("WithDefaults overwrote explicit values: %+v", got)
	}
}

// Backoff caps at MaxBackoff however high the attempt goes: an unbounded
// shift would sleep for hours on attempt 30.
func TestBackoffHonoursMaxBackoff(t *testing.T) {
	cfg := adcore.RetryConfig{InitialBackoff: time.Millisecond, MaxBackoff: 20 * time.Millisecond}
	start := time.Now()
	if err := adcore.Backoff(context.Background(), cfg, 30); err != nil {
		t.Fatalf("Backoff: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Backoff slept %v on attempt 30; MaxBackoff was %v", elapsed, cfg.MaxBackoff)
	}
}

// A cancelled caller must not be held for the full delay, and the error must
// be a transport failure — never transient, which would invite a re-issue.
func TestBackoffHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := adcore.Backoff(ctx, adcore.RetryConfig{InitialBackoff: time.Hour, MaxBackoff: time.Hour}, 1)
	var e *adcore.Error
	if !errors.As(err, &e) || e.Kind != adcore.KindTransport {
		t.Fatalf("want a KindTransport adcore.Error, got %#v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Error("the cancellation cause must stay reachable through Unwrap")
	}
}
