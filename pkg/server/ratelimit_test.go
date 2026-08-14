package server

import (
	"testing"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/core"
)

func fixedClock(ts time.Time) func() time.Time {
	return func() time.Time { return ts }
}

func newTestLimiter(rps, burst int) *Limiter {
	l := NewLimiter(RateLimitConfig{
		RequestsPerSecond: rps,
		Burst:             burst,
	})
	return l
}

func TestLimiter_AllowsBurstThenThrottles(t *testing.T) {
	l := newTestLimiter(10, 3)
	start := time.Unix(1000, 0)
	l.now = fixedClock(start)

	fp := Fingerprint(core.CallerIdentity{ClientID: "sales-copilot"})
	// Burst of 3 must all succeed immediately.
	for i := 0; i < 3; i++ {
		ok, _ := l.Allow(fp, 0)
		if !ok {
			t.Fatalf("burst request %d should pass", i)
		}
	}
	// Fourth request must be refused.
	ok, retryAfter := l.Allow(fp, 0)
	if ok {
		t.Fatal("fourth request must be throttled")
	}
	if retryAfter < time.Second {
		t.Fatalf("retry hint too short: %v", retryAfter)
	}
}

func TestLimiter_RefillsOverTime(t *testing.T) {
	start := time.Unix(1000, 0)
	l := newTestLimiter(10, 2)
	var clockAt time.Time
	l.now = func() time.Time { return clockAt }
	clockAt = start

	fp := Fingerprint(core.CallerIdentity{ClientID: "etl-worker"})
	l.Allow(fp, 0) // tokens: 1
	l.Allow(fp, 0) // tokens: 0

	clockAt = start.Add(50 * time.Millisecond)
	ok, _ := l.Allow(fp, 0)
	if ok {
		t.Fatal("must still be throttled at 50ms (0.5 tokens)")
	}

	// After 150ms total, one full token has refilled.
	clockAt = start.Add(150 * time.Millisecond)
	ok, _ = l.Allow(fp, 0)
	if !ok {
		t.Fatal("must allow after a full token refills")
	}
}

func TestLimiter_PerIdentityOverride(t *testing.T) {
	start := time.Unix(1000, 0)
	l := newTestLimiter(10, 1)
	var clockAt time.Time
	l.now = func() time.Time { return clockAt }
	clockAt = start

	fp := Fingerprint(core.CallerIdentity{ClientID: "crawler"})
	// Base rate 10 RPS, override 50 RPS → 5 tokens/sec.
	clockAt = start
	for i := 0; i < 5; i++ {
		clockAt = start.Add(time.Duration(i*200) * time.Millisecond)
		ok, _ := l.Allow(fp, 50)
		if !ok {
			t.Fatalf("crawler request %d at %v should pass", i, clockAt.Sub(start))
		}
	}
	// 5th request at t=0 with refills at 1 token/200ms... actually with
	// 5 RPS and sequential 200ms spacing, exactly 5 requests pass.
	clockAt = start.Add(1000 * time.Millisecond)
	ok, _ := l.Allow(fp, 50)
	if !ok {
		t.Fatal("crawler must keep its 50 RPS pace")
	}
}

func TestLimiter_IdentitiesAreIsolated(t *testing.T) {
	l := newTestLimiter(10, 2)
	start := time.Unix(1000, 0)
	l.now = fixedClock(start)

	a := Fingerprint(core.CallerIdentity{ClientID: "svc-a"})
	b := Fingerprint(core.CallerIdentity{ClientID: "svc-b"})
	l.Allow(a, 0)
	l.Allow(a, 0)
	if ok, _ := l.Allow(a, 0); ok {
		t.Fatal("svc-a should be exhausted")
	}
	if ok, _ := l.Allow(b, 0); !ok {
		t.Fatal("svc-b must be unaffected by svc-a")
	}
}

func TestLimiter_FingerprintDeterminism(t *testing.T) {
	id := core.CallerIdentity{ClientID: "x", TokenHash: "h", MTLSSubject: "s"}
	f1 := Fingerprint(id)
	f2 := Fingerprint(id)
	if f1 != f2 {
		t.Fatal("fingerprint must be deterministic")
	}
	// Different identity → different bucket key.
	id2 := core.CallerIdentity{ClientID: "y", TokenHash: "h", MTLSSubject: "s"}
	if Fingerprint(id) == Fingerprint(id2) {
		t.Fatal("distinct identities must not collide")
	}
}

func TestLimiter_Prune(t *testing.T) {
	l := newTestLimiter(10, 2)
	start := time.Unix(1000, 0)
	var clockAt time.Time
	l.now = func() time.Time { return clockAt }
	clockAt = start

	fp := Fingerprint(core.CallerIdentity{ClientID: "tmp"})
	l.Allow(fp, 0)
	if l.Size() != 1 {
		t.Fatal("expected one tracked identity")
	}
	clockAt = start.Add(5 * time.Minute)
	pruned := l.Prune(time.Minute)
	if pruned != 1 || l.Size() != 0 {
		t.Fatalf("expected 1 pruned, got %d", pruned)
	}
}

func TestLimiter_DefaultConfig(t *testing.T) {
	cfg := DefaultRateLimitConfig()
	if cfg.RequestsPerSecond != 10 || cfg.Burst != 20 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}
