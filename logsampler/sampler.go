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

// clock is an interface for getting the current time.
// It's used to allow for mocking time in tests.
type clock interface {
	Now() time.Time
}

// systemClock implements the clock interface using the system's time.
type systemClock struct{}

func (c systemClock) Now() time.Time {
	return time.Now()
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

// --- New EventDrivenSampler ---

const (
	// cleanupInterval controls how often we perform cleanup operations
	// This is measured in number of operations, not time
	cleanupInterval = 1
)

// eventLogInfo holds the state for a key in the EventDrivenSampler.
// It also acts as a node in a doubly-linked list for LRU-style eviction.
type eventLogInfo struct {
	key             string
	suppressedCount atomic.Int64
	lastLogTime     int64
	activeWindow    int64

	// Pointers for the doubly-linked list
	prev *eventLogInfo
	next *eventLogInfo
}

// EventDrivenSampler provides high-performance, adaptive sampling without background goroutines.
// It uses a map for fast lookups and a doubly-linked list for efficient time-based ordering.
type EventDrivenSampler struct {
	config   BackoffConfig
	reporter SummaryReporter
	clock    clock
	mu       sync.Mutex
	logs     map[string]*eventLogInfo
	opCount  atomic.Uint64 // Counter used to amortize cleanup cost

	// Head and tail of the doubly-linked list for LRU-style cleanup.
	// Head is the oldest, Tail is the newest.
	head *eventLogInfo
	tail *eventLogInfo
}

// NewEventDrivenSampler creates a new sampler that operates without a background goroutine.
// It requires a SummaryReporter to log summaries of stale keys.
func NewEventDrivenSampler(config BackoffConfig, reporter SummaryReporter) *EventDrivenSampler {
	if reporter == nil {
		return nil
	}
	s := &EventDrivenSampler{
		config:   config,
		reporter: reporter,
		clock:    systemClock{},
		logs:     make(map[string]*eventLogInfo, 64),
	}
	return s
}

// ShouldLog determines if an event should be logged based on its adaptive strategy.
func (s *EventDrivenSampler) ShouldLog(key string, err error) (bool, int64) {
	now := s.clock.Now().UnixNano()

	// Periodically check for stale entries. This check is done outside the main lock.
	if s.config.ResetInterval > 0 && s.opCount.Add(1)&(cleanupInterval-1) == 0 {
		s.mu.Lock()
		s.cleanupStaleKeys(now)
		s.mu.Unlock()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	info, exists := s.logs[key]
	if !exists {
		info = &eventLogInfo{
			key:          key,
			lastLogTime:  now,
			activeWindow: int64(s.config.InitialInterval),
		}
		s.logs[key] = info
		s.pushToFront(info) // Add to the list as the newest entry.
		return true, 0
	}

	// Move the accessed entry to the front of the list to mark it as recently used.
	s.moveToFront(info)

	// Reset backoff if the key has been inactive for the configured reset interval.
	if s.config.ResetInterval > 0 && now-info.lastLogTime > int64(s.config.ResetInterval) {
		suppressed := info.suppressedCount.Swap(0)
		info.activeWindow = int64(s.config.InitialInterval)
		info.lastLogTime = now
		return true, suppressed
	}

	// Check if the active quiet window has passed.
	if now-info.lastLogTime > info.activeWindow {
		suppressed := info.suppressedCount.Swap(0)
		info.lastLogTime = now

		// Calculate and activate the next backoff window.
		nextWindow := int64(float64(info.activeWindow) * s.config.Factor)
		if maxInterval := int64(s.config.MaxInterval); nextWindow > maxInterval {
			nextWindow = maxInterval
		}
		info.activeWindow = nextWindow
		return true, suppressed
	}

	// We are within the quiet window; suppress the log.
	info.suppressedCount.Add(1)
	return false, 0
}

// cleanupStaleKeys removes stale keys by walking the linked list from the oldest entry.
// This must be called with the mutex held.
func (s *EventDrivenSampler) cleanupStaleKeys(now int64) {
	if s.config.ResetInterval <= 0 {
		return
	}
	staleThreshold := now - int64(s.config.ResetInterval)

	// Walk from the tail (oldest) and remove stale entries.
	for s.tail != nil && s.tail.lastLogTime < staleThreshold {
		staleNode := s.tail
		if suppressed := staleNode.suppressedCount.Swap(0); suppressed > 0 {
			s.reporter.LogSummary(staleNode.key, suppressed)
		}
		delete(s.logs, staleNode.key)
		s.removeNode(staleNode)
	}
}

// --- Linked List Helpers (must be called with mutex held) ---

// removeNode removes an element from the linked list. O(1).
func (s *EventDrivenSampler) removeNode(info *eventLogInfo) {
	if info.prev != nil {
		info.prev.next = info.next
	} else {
		s.head = info.next // It was the head
	}
	if info.next != nil {
		info.next.prev = info.prev
	} else {
		s.tail = info.prev // It was the tail
	}
}

// pushToFront adds an element to the front (head) of the list. O(1).
func (s *EventDrivenSampler) pushToFront(info *eventLogInfo) {
	info.next = s.head
	info.prev = nil
	if s.head != nil {
		s.head.prev = info
	}
	s.head = info
	if s.tail == nil {
		s.tail = info
	}
}

// moveToFront moves an existing element to the front of the list. O(1).
func (s *EventDrivenSampler) moveToFront(info *eventLogInfo) {
	if s.head == info {
		return // Already at the front
	}
	s.removeNode(info)
	s.pushToFront(info)
}

// Flush reports a summary of all suppressed logs and clears the sampler state.
func (s *EventDrivenSampler) Flush() {
    s.mu.Lock()
    defer s.mu.Unlock()

    for key, info := range s.logs {
        if suppressed := info.suppressedCount.Swap(0); suppressed > 0 {
            s.reporter.LogSummary(key, suppressed)
        }
    }

    // Clear all state
    s.logs = make(map[string]*eventLogInfo, 64)
    s.head = nil
    s.tail = nil
    s.opCount.Store(0)
}

// Close is functionally equivalent to Flush for this sampler.
func (s *EventDrivenSampler) Close() {
	s.Flush()
}

// This is a temporary helper for testing to allow injection of a mock clock.
func (s *EventDrivenSampler) SetClock(c clock) {
	s.clock = c
}
