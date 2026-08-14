package server

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/core"
)

// Fingerprint returns the deterministic identity key used by both the
// rate limiter (Ticket 16) and the PagerDuty observer (Ticket 12):
// SHA-256(ClientID|TokenHash|MTLSSubject). Empty components still
// contribute to the key, so an anonymous caller and a named caller
// never collide.
func Fingerprint(id core.CallerIdentity) string {
	payload := id.ClientID + "|" + id.TokenHash + "|" + id.MTLSSubject
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// RateLimitConfig is the YAML surface in config.yaml.
type RateLimitConfig struct {
	Enabled          bool          `yaml:"enabled"`
	RequestsPerSecond int          `yaml:"requests_per_second"`
	Burst            int           `yaml:"burst"`
	Window           time.Duration `yaml:"window"`
	// IncludeInAlerts opts PagerDuty into rate-limit events (default: off).
	IncludeInAlerts bool `yaml:"include_in_alerts"`
}

// DefaultRateLimitConfig returns the production defaults (10 RPS, burst 20).
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 10,
		Burst:             20,
		Window:            time.Minute,
	}
}

// Limiter is a per-key token bucket. Tokens refill at the configured
// rate up to the burst ceiling. Allow() is O(1) and safe for
// concurrent callers; stale buckets are pruned lazily.
type Limiter struct {
	mu       sync.Mutex
	cfg      RateLimitConfig
	buckets  map[string]*bucket
	rate     float64   // tokens per second
	burst    float64   // bucket ceiling
	pruneEvery time.Duration
	now      func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewLimiter builds a limiter from config.
func NewLimiter(cfg RateLimitConfig) *Limiter {
	if cfg.RequestsPerSecond <= 0 {
		cfg.RequestsPerSecond = 10
	}
	if cfg.Burst <= 0 {
		cfg.Burst = 20
	}
	return &Limiter{
		cfg:        cfg,
		buckets:    make(map[string]*bucket),
		rate:       float64(cfg.RequestsPerSecond),
		burst:      float64(cfg.Burst),
		pruneEvery: time.Minute,
		now:        time.Now,
	}
}

// Enabled reports whether the limiter will enforce budgets. The gateway
// consults this before wiring rate-limiting into the request path so a
// disabled limiter is pure no-op overhead.
func (l *Limiter) Enabled() bool {
	return l.cfg.Enabled
}

// Allow reports whether the fingerprint may proceed, consuming one
// token on success. The optional per-identity override scales the
// bucket (a crawler rule granting 50 RPS multiplies the base rate by
// 5 relative to the 10 RPS default).
func (l *Limiter) Allow(fingerprint string, overrideRPS int) (bool, time.Duration) {
	l.mu.Lock()
	b, ok := l.buckets[fingerprint]
	if !ok {
		b = &bucket{tokens: l.burst, last: l.now()}
		l.buckets[fingerprint] = b
	}
	rate := l.rate
	if overrideRPS > 0 {
		// Per-identity allowance scales linearly against the base rate.
		rate = l.rate * float64(overrideRPS) / 10.0
	}
	burst := l.burst
	if overrideRPS > 0 {
		burst = l.burst * float64(overrideRPS) / 10.0
	}
	now := l.now()
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
	var retryAfter time.Duration
	allowed := b.tokens >= 1.0
	if allowed {
		b.tokens--
	} else {
		// Time until one token refills, rounded up.
		retryAfter = time.Duration((1.0 - b.tokens) / rate * float64(time.Second))
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
	}
	l.mu.Unlock()
	return allowed, retryAfter
}

// Prune removes buckets idle longer than the cleanup window. Called
// by the server on a ticker; safe to no-op if never called.
func (l *Limiter) Prune(maxIdle time.Duration) int {
	if maxIdle == 0 {
		maxIdle = time.Minute
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.now().Add(-maxIdle)
	pruned := 0
	for k, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, k)
			pruned++
		}
	}
	return pruned
}

// Size returns the current number of tracked identities (tests).
func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
