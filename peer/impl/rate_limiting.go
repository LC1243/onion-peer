package impl

import (
	"sync"
	"time"
)

type TokenBucket struct {
	rate       float64   // tokens added per second
	capacity   float64   // maximum number of tokens
	tokens     float64   // current number of tokens
	lastRefill time.Time // last time tokens were updated (in seconds)
	mu         sync.Mutex
}

func NewTokenBucket(rate, capacity float64) *TokenBucket {
	return &TokenBucket{
		rate:       rate,
		capacity:   capacity,
		tokens:     capacity, // Start full
		lastRefill: time.Now(),
	}
}

func (tb *TokenBucket) Consume(amount float64) time.Duration {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Determine elapsed time since last refill and refill tokens lazily.
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()

	// Refill tokens according to elapsed time and rate
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		// Cap at capacity to ensure we don't grow beyond the configured burst
		tb.tokens = tb.capacity
	}
	tb.lastRefill = now

	// If there are enough tokens, consume immediately and allow send
	if tb.tokens >= amount {
		tb.tokens -= amount
		return 0
	}

	// Not enough tokens: compute missing tokens and the wait time
	missing := amount - tb.tokens
	// Wait time = missing tokens / rate (converted to time.Duration)
	waitTime := time.Duration((missing / tb.rate) * float64(time.Second))

	// Reserve the tokens by subtracting the requested amount. This may drive
	// the token count negative; negative values represent a debt that will be
	// corrected by future refill operations. Reserving here prevents races in
	// which multiple callers compute the same waitTime and proceed in parallel.
	tb.tokens -= amount

	return waitTime
}
