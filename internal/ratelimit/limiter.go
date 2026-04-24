// Package ratelimit provides token bucket and adaptive rate limiting.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter provides token-bucket rate limiting.
type Limiter struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

// NewLimiter creates a new token bucket rate limiter.
// rate: requests per second, burst: max burst size.
func NewLimiter(rate float64, burst int) *Limiter {
	return &Limiter{
		tokens:     float64(burst),
		maxTokens:  float64(burst),
		refillRate: rate,
		lastRefill: time.Now(),
	}
}

// Wait blocks until a token is available or context is cancelled.
func (l *Limiter) Wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		l.refill()

		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}

		// Calculate wait time for next token
		waitTime := time.Duration(float64(time.Second) / l.refillRate)
		l.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
			// Try again
		}
	}
}

// TryAcquire attempts to acquire a token without blocking.
func (l *Limiter) TryAcquire() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.refill()

	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}

// Available returns the current number of available tokens.
func (l *Limiter) Available() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refill()
	return int(l.tokens)
}

// SetRate dynamically updates the rate limit.
func (l *Limiter) SetRate(rate float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refill()
	l.refillRate = rate
}

func (l *Limiter) refill() {
	now := time.Now()
	elapsed := now.Sub(l.lastRefill).Seconds()
	l.tokens += elapsed * l.refillRate
	if l.tokens > l.maxTokens {
		l.tokens = l.maxTokens
	}
	l.lastRefill = now
}
