package logsampler

import (
	"sync/atomic"
	"time"
)

// RateSampler provides simple, high-performance rate-based sampling.
type RateSampler struct {
	rate   int64
	window int64
	count  atomic.Int64
	last   atomic.Int64
}

// NewRateSampler creates a new rate sampler.
func NewRateSampler(rate int, window time.Duration) *RateSampler {
	s := &RateSampler{
		rate:   int64(rate),
		window: int64(window),
	}
	s.last.Store(time.Now().UnixNano())
	return s
}

// ShouldLog returns true if this event should be logged based on the rate limit.
func (s *RateSampler) ShouldLog(key string, err error) (bool, int64) {
	now := time.Now().UnixNano()
	lastReset := s.last.Load()

	if now-lastReset > s.window {
		if s.last.CompareAndSwap(lastReset, now) {
			s.count.Store(0)
		}
	}
	return (s.count.Add(1)-1)%s.rate == 0, 0 // RateSampler doesn't track suppressed counts.
}

// Flush is a no-op for the simple RateSampler.
func (s *RateSampler) Flush() {}

// Close is a no-op for RateSampler.
func (s *RateSampler) Close() {}
