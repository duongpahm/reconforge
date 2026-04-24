package ratelimit

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

// AdaptiveLimiter adjusts rate based on server response feedback (429/503 detection).
type AdaptiveLimiter struct {
	limiter  *Limiter
	mu       sync.RWMutex
	logger   zerolog.Logger

	// Config
	minRate     float64
	maxRate     float64
	backoffFactor float64 // multiply rate by this on error (e.g., 0.5)
	recoveryFactor float64 // multiply rate by this on success (e.g., 1.1)
	recoveryWindow int     // successive successes before recovery

	// State
	currentRate     float64
	consecutiveOK   atomic.Int64
	consecutiveFail atomic.Int64
	totalThrottled  atomic.Int64
	lastBackoff     time.Time
}

// AdaptiveConfig configures the adaptive rate limiter.
type AdaptiveConfig struct {
	MinRate        float64 // minimum requests/sec
	MaxRate        float64 // maximum requests/sec
	InitialRate    float64 // starting requests/sec
	BackoffFactor  float64 // rate multiplier on throttle (default: 0.5)
	RecoveryFactor float64 // rate multiplier on recovery (default: 1.1)
	RecoveryWindow int     // successes before recovery (default: 10)
	BurstSize      int     // token bucket burst
}

// NewAdaptiveLimiter creates a new adaptive rate limiter.
func NewAdaptiveLimiter(cfg AdaptiveConfig, logger zerolog.Logger) *AdaptiveLimiter {
	if cfg.BackoffFactor == 0 {
		cfg.BackoffFactor = 0.5
	}
	if cfg.RecoveryFactor == 0 {
		cfg.RecoveryFactor = 1.1
	}
	if cfg.RecoveryWindow == 0 {
		cfg.RecoveryWindow = 10
	}
	if cfg.BurstSize == 0 {
		cfg.BurstSize = int(cfg.InitialRate)
		if cfg.BurstSize < 1 {
			cfg.BurstSize = 1
		}
	}

	al := &AdaptiveLimiter{
		limiter:        NewLimiter(cfg.InitialRate, cfg.BurstSize),
		logger:         logger,
		minRate:        cfg.MinRate,
		maxRate:        cfg.MaxRate,
		currentRate:    cfg.InitialRate,
		backoffFactor:  cfg.BackoffFactor,
		recoveryFactor: cfg.RecoveryFactor,
		recoveryWindow: cfg.RecoveryWindow,
	}

	return al
}

// Limiter returns the underlying token bucket limiter.
func (al *AdaptiveLimiter) Limiter() *Limiter {
	return al.limiter
}

// RecordSuccess records a successful request.
func (al *AdaptiveLimiter) RecordSuccess() {
	al.consecutiveOK.Add(1)
	al.consecutiveFail.Store(0)

	if int(al.consecutiveOK.Load()) >= al.recoveryWindow {
		al.recover()
		al.consecutiveOK.Store(0)
	}
}

// RecordThrottle records a throttled response (429/503/rate-limited).
func (al *AdaptiveLimiter) RecordThrottle() {
	al.consecutiveFail.Add(1)
	al.consecutiveOK.Store(0)
	al.totalThrottled.Add(1)

	al.backoff()
}

// RecordHTTPStatus processes an HTTP status and auto-detects throttling.
func (al *AdaptiveLimiter) RecordHTTPStatus(statusCode int) {
	switch {
	case statusCode == 429, statusCode == 503:
		al.RecordThrottle()
	case statusCode >= 200 && statusCode < 400:
		al.RecordSuccess()
	}
}

func (al *AdaptiveLimiter) backoff() {
	al.mu.Lock()
	defer al.mu.Unlock()

	newRate := al.currentRate * al.backoffFactor
	if newRate < al.minRate {
		newRate = al.minRate
	}

	al.logger.Warn().
		Float64("old_rate", al.currentRate).
		Float64("new_rate", newRate).
		Int64("total_throttled", al.totalThrottled.Load()).
		Msg("Rate limited — backing off")

	al.currentRate = newRate
	al.limiter.SetRate(newRate)
	al.lastBackoff = time.Now()
}

func (al *AdaptiveLimiter) recover() {
	al.mu.Lock()
	defer al.mu.Unlock()

	// Don't recover too soon after a backoff
	if time.Since(al.lastBackoff) < 5*time.Second {
		return
	}

	newRate := al.currentRate * al.recoveryFactor
	if newRate > al.maxRate {
		newRate = al.maxRate
	}

	if newRate != al.currentRate {
		al.logger.Debug().
			Float64("old_rate", al.currentRate).
			Float64("new_rate", newRate).
			Msg("Recovering rate")

		al.currentRate = newRate
		al.limiter.SetRate(newRate)
	}
}

// CurrentRate returns the current rate limit.
func (al *AdaptiveLimiter) CurrentRate() float64 {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return al.currentRate
}

// Stats returns adaptive limiter statistics.
func (al *AdaptiveLimiter) Stats() AdaptiveStats {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return AdaptiveStats{
		CurrentRate:    al.currentRate,
		MinRate:        al.minRate,
		MaxRate:        al.maxRate,
		TotalThrottled: al.totalThrottled.Load(),
	}
}

// AdaptiveStats holds rate limiter statistics.
type AdaptiveStats struct {
	CurrentRate    float64 `json:"current_rate"`
	MinRate        float64 `json:"min_rate"`
	MaxRate        float64 `json:"max_rate"`
	TotalThrottled int64   `json:"total_throttled"`
}
