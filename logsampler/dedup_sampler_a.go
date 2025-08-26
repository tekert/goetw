package logsampler

import (
	"sync"
	"sync/atomic"
	"time"
)

// uses goroutine, uses sync.Map for storage

// logInfo holds the sampling state for a given log key.
type logInfo struct {
	suppressedCount atomic.Int64
	lastLogTime     atomic.Int64
	// activeWindow is the duration of the quiet window that started after the last log.
	activeWindow atomic.Int64
}

// DeduplicatingSampler provides high-performance, adaptive sampling with exponential backoff.
// Deprecated: This sampler uses a background goroutine. Use EventDrivenSampler for a goroutine-free alternative
// that offers simpler lifecycle management.
type DeduplicatingSampler struct {
	config   BackoffConfig
	logs     sync.Map
	stopCh   chan struct{}
	reporter SummaryReporter
}

// NewDeduplicatingSampler creates a new sampler with exponential backoff.
// Deprecated: This sampler uses a background goroutine. Use NewEventDrivenSampler for a goroutine-free alternative.
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
	// The ticker determines how frequently we check for inactive keys.
	// A moderate interval is a good balance between responsiveness and overhead.
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	// Determine the threshold for considering a key "inactive".
	// If ResetInterval is configured, it's the best indicator of inactivity.
	// Otherwise, we use a generous multiple of the max backoff interval.
	inactivityThreshold := s.config.ResetInterval
	if inactivityThreshold <= 0 {
		inactivityThreshold = s.config.MaxInterval * 2
	}
	// Ensure a minimum threshold to avoid overly aggressive cleanup.
	if inactivityThreshold < 1*time.Minute {
		inactivityThreshold = 1 * time.Minute
	}
	inactivityThresholdNanos := int64(inactivityThreshold)

	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			s.logs.Range(func(key, value any) bool {
				info := value.(*logInfo)
				lastLog := info.lastLogTime.Load()

				// If a key hasn't logged anything for the configured inactivity period,
				// report its summary and remove it to prevent memory leaks.
				if now-lastLog > inactivityThresholdNanos {
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
// Deprecated: This sampler uses a background goroutine. Use EventDrivenSampler for a goroutine-free alternative.
func (s *DeduplicatingSampler) Close() {
	if s.reporter != nil {
		close(s.stopCh)
		s.flushSummaries()
	}
}
