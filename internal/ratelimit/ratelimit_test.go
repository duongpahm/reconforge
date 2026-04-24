package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLimiter_Wait(t *testing.T) {
	l := NewLimiter(100, 5) // 100/sec, burst of 5

	// Should get 5 immediately (burst)
	for i := 0; i < 5; i++ {
		err := l.Wait(context.Background())
		require.NoError(t, err)
	}
}

func TestLimiter_TryAcquire(t *testing.T) {
	l := NewLimiter(10, 3)

	// Should succeed 3 times (burst)
	assert.True(t, l.TryAcquire())
	assert.True(t, l.TryAcquire())
	assert.True(t, l.TryAcquire())

	// Should fail when burst exhausted
	assert.False(t, l.TryAcquire())
}

func TestLimiter_RefillOverTime(t *testing.T) {
	l := NewLimiter(100, 1) // 100/sec, burst 1

	// Exhaust
	l.TryAcquire()
	assert.False(t, l.TryAcquire())

	// Wait for refill
	time.Sleep(15 * time.Millisecond)
	assert.True(t, l.TryAcquire())
}

func TestLimiter_ContextCancellation(t *testing.T) {
	l := NewLimiter(1, 0) // Very slow, no burst

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := l.Wait(ctx)
	assert.Error(t, err)
}

func TestLimiter_SetRate(t *testing.T) {
	l := NewLimiter(1, 1)
	l.TryAcquire() // exhaust

	l.SetRate(1000) // speed up
	time.Sleep(5 * time.Millisecond)
	assert.True(t, l.TryAcquire())
}

func TestAdaptiveLimiter_Backoff(t *testing.T) {
	al := NewAdaptiveLimiter(AdaptiveConfig{
		MinRate:     10,
		MaxRate:     100,
		InitialRate: 100,
		BackoffFactor: 0.5,
	}, zerolog.Nop())

	assert.InDelta(t, 100.0, al.CurrentRate(), 0.1)

	al.RecordThrottle()
	assert.InDelta(t, 50.0, al.CurrentRate(), 0.1) // 100 * 0.5

	al.RecordThrottle()
	assert.InDelta(t, 25.0, al.CurrentRate(), 0.1) // 50 * 0.5

	al.RecordThrottle()
	assert.InDelta(t, 12.5, al.CurrentRate(), 0.1)

	al.RecordThrottle()
	assert.InDelta(t, 10.0, al.CurrentRate(), 0.1) // clamped to min
}

func TestAdaptiveLimiter_Recovery(t *testing.T) {
	al := NewAdaptiveLimiter(AdaptiveConfig{
		MinRate:        10,
		MaxRate:        100,
		InitialRate:    50,
		RecoveryFactor: 2.0,
		RecoveryWindow: 3,
	}, zerolog.Nop())

	// Record enough successes to trigger recovery
	for i := 0; i < 3; i++ {
		al.RecordSuccess()
	}

	rate := al.CurrentRate()
	assert.Greater(t, rate, 50.0)   // should have recovered
	assert.LessOrEqual(t, rate, 100.0) // capped at max
}

func TestAdaptiveLimiter_HTTPStatus(t *testing.T) {
	al := NewAdaptiveLimiter(AdaptiveConfig{
		MinRate:     10,
		MaxRate:     100,
		InitialRate: 100,
	}, zerolog.Nop())

	al.RecordHTTPStatus(200) // OK
	assert.Equal(t, int64(0), al.Stats().TotalThrottled)

	al.RecordHTTPStatus(429) // Rate limited
	assert.Equal(t, int64(1), al.Stats().TotalThrottled)

	al.RecordHTTPStatus(503) // Service unavailable
	assert.Equal(t, int64(2), al.Stats().TotalThrottled)
}

func TestAdaptiveLimiter_MinRateFloor(t *testing.T) {
	al := NewAdaptiveLimiter(AdaptiveConfig{
		MinRate:     50,
		MaxRate:     100,
		InitialRate: 60,
		BackoffFactor: 0.5,
	}, zerolog.Nop())

	al.RecordThrottle() // 60 * 0.5 = 30, but min is 50
	assert.InDelta(t, 50.0, al.CurrentRate(), 0.1)
}
