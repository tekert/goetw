/*
Package sampler provides high-performance, concurrent-safe log sampling strategies.
It is designed for use in hot paths of applications where logging every event would
be prohibitively expensive, such as high-frequency error reporting or verbose tracing.
*/
package logsampler

import (
	"sync"
	"sync/atomic"
	"time"
)

// BackoffConfig defines the parameters for the exponential backoff strategy.
type BackoffConfig struct {
	InitialInterval time.Duration // The base quiet window after a log is emitted.
	MaxInterval     time.Duration // The maximum quiet window.
	Factor          float64       // The multiplication factor for the window (e.g., 2.0).
	// ResetInterval is the duration of inactivity after which the backoff window for a key is reset to InitialInterval.
	// If zero, the backoff window never resets.
	ResetInterval time.Duration
}

// SummaryReporter defines the interface for a logger that can report
// sampler summaries for inactive keys.
// This allows the sampler to remain decoupled from any
// specific logging library.
type SummaryReporter interface {
	LogSummary(key string, suppressedCount int64)
}

// Sampler defines the interface for deciding if a log message should be processed.
type Sampler interface {
	// ShouldLog determines if a log event should be written.
	// It returns true if the event should be logged. If true, it also returns
	// the number of events that were suppressed since the last logged event for that key.
	ShouldLog(key string, err error) (bool, int64)
	// Flush reports a summary of any suppressed logs.
	Flush()
	// Close permanently stops the sampler and its background tasks, flushing one last time.
	Close()
}

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

// logInfo holds the sampling state for a given log key.
type logInfo struct {
	suppressedCount atomic.Int64
	lastLogTime     atomic.Int64
	// activeWindow is the duration of the quiet window that started after the last log.
	activeWindow atomic.Int64
}

// DeduplicatingSampler provides high-performance, adaptive sampling with exponential backoff.
type DeduplicatingSampler struct {
	config   BackoffConfig
	logs     sync.Map
	stopCh   chan struct{}
	reporter SummaryReporter
}

// NewDeduplicatingSampler creates a new sampler with exponential backoff.
func NewDeduplicatingSampler(config BackoffConfig, reporter SummaryReporter) *DeduplicatingSampler {
	s := &DeduplicatingSampler{
		config:   config,
		stopCh:   make(chan struct{}),
		reporter: reporter,
	}
	if s.reporter != nil {
		go s.garbageCollector()
	}
	return s
}

// ShouldLog determines if an event should be logged based on its adaptive strategy.
func (s *DeduplicatingSampler) ShouldLog(key string, err error) (bool, int64) {
	now := time.Now().UnixNano()
	val, _ := s.logs.LoadOrStore(key, &logInfo{})
	info := val.(*logInfo)

	lastLog := info.lastLogTime.Load()

	// Reset backoff if the key has been inactive for the configured reset interval.
	if lastLog != 0 && s.config.ResetInterval > 0 {
		if now-lastLog > int64(s.config.ResetInterval) {
			// By resetting the window, the next check will behave as if the quiet period
			// has passed, allowing the log and starting the backoff sequence over.
			info.activeWindow.Store(int64(s.config.InitialInterval))
		}
	}

	// The first log for a key always passes. This also serves as initialization.
	if lastLog == 0 {
		if info.lastLogTime.CompareAndSwap(0, now) {
			// The first quiet window is the initial interval.
			info.activeWindow.Store(int64(s.config.InitialInterval))
			return true, 0
		}
		// If we lost the race to initialize, another goroutine won. We must suppress this event
		// and let the next event be evaluated against the newly set window.
		info.suppressedCount.Add(1)
		return false, 0
	}

	activeWindow := info.activeWindow.Load()

	// Check if the active quiet window has passed.
	if now-lastLog > activeWindow {
		if info.lastLogTime.CompareAndSwap(lastLog, now) {
			suppressed := info.suppressedCount.Swap(0)

			// Calculate and activate the *next* backoff window.
			nextWindow := int64(float64(activeWindow) * s.config.Factor)
			if maxInterval := int64(s.config.MaxInterval); nextWindow > maxInterval {
				nextWindow = maxInterval
			}
			info.activeWindow.Store(nextWindow)

			return true, suppressed
		}
		// If we lost the race, another goroutine just logged. We must suppress.
	}

	// We are within the quiet window; suppress the log.
	info.suppressedCount.Add(1)
	return false, 0
}

// Flush triggers an immediate summary report of all currently suppressed logs.
func (s *DeduplicatingSampler) Flush() {
	s.flushSummaries()
}

func (s *DeduplicatingSampler) flushSummaries() {
	if s.reporter == nil {
		return
	}
	s.logs.Range(func(key, value any) bool {
		info := value.(*logInfo)
		if suppressedCount := info.suppressedCount.Load(); suppressedCount > 0 {
			s.reporter.LogSummary(key.(string), suppressedCount)
		}
		s.logs.Delete(key)
		return true
	})
}

// garbageCollector is a background task that cleans up inactive keys to prevent memory leaks.
func (s *DeduplicatingSampler) garbageCollector() {
	// Run GC less frequently, e.g., every 2x the max interval.
	tickerInterval := max(s.config.MaxInterval*2, 1*time.Minute)
	ticker := time.NewTicker(tickerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			s.logs.Range(func(key, value any) bool {
				info := value.(*logInfo)
				lastLog := info.lastLogTime.Load()

				// If a key hasn't logged anything for a long time, it's considered inactive.
				if now-lastLog > int64(tickerInterval) {
					// Before deleting, flush any lingering suppressed count.
					if suppressed := info.suppressedCount.Swap(0); suppressed > 0 {
						s.reporter.LogSummary(key.(string), suppressed)
					}
					s.logs.Delete(key)
				}
				return true
			})
		case <-s.stopCh:
			return
		}
	}
}

// Close stops the background summary reporter and flushes any pending summaries.
func (s *DeduplicatingSampler) Close() {
	if s.reporter != nil {
		close(s.stopCh)
		s.flushSummaries()
	}
}
