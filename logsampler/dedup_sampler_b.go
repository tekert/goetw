package logsampler

import (
	"sync"
	"sync/atomic"
	"time"
)

// --- New EventDrivenSampler --- (no goroutine, uses doubly-linked list for LRU cleanup) ---

const (
	// cleanupInterval controls how often we perform cleanup operations
	// This is measured in number of operations, not time
	cleanupInterval = 1
)

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

	s.mu.Lock()
	defer s.mu.Unlock()

	var shouldLog bool
	var suppressedCount int64

	info, exists := s.logs[key]
	if !exists {
		// This is the first time we've seen this key.
		info = &eventLogInfo{
			key:          key,
			lastLogTime:  now,
			activeWindow: int64(s.config.InitialInterval),
		}
		s.logs[key] = info
		s.pushToFront(info) // Add to the list as the newest entry.
		shouldLog = true
		suppressedCount = 0
	} else {
		// The key already exists.
		s.moveToFront(info) // Mark it as recently used.

		// Check if the key is stale and needs its backoff reset.
		if s.config.ResetInterval > 0 && now-info.lastLogTime > int64(s.config.ResetInterval) {
			suppressedCount = info.suppressedCount.Swap(0)
			info.activeWindow = int64(s.config.InitialInterval)
			info.lastLogTime = now
			shouldLog = true
		} else if now-info.lastLogTime > info.activeWindow {
			// Check if the active quiet window has passed.
			suppressedCount = info.suppressedCount.Swap(0)
			info.lastLogTime = now
			// Calculate and activate the next backoff window.
			nextWindow := int64(float64(info.activeWindow) * s.config.Factor)
			if maxInterval := int64(s.config.MaxInterval); nextWindow > maxInterval {
				nextWindow = maxInterval
			}
			info.activeWindow = nextWindow
			shouldLog = true
		} else {
			// We are within the quiet window; suppress the log.
			info.suppressedCount.Add(1)
			shouldLog = false
			suppressedCount = 0
		}
	}

	// Now that the logic for the current key is complete, run the opportunistic cleanup
	// for other, unrelated stale keys.
	if s.config.ResetInterval > 0 && s.opCount.Add(1)&(cleanupInterval-1) == 0 {
		s.cleanupStaleKeys(now)
	}

	return shouldLog, suppressedCount
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

//   (head)A <-> B <-> C <-> D(tail)
// nil<-prev      ...        next->nil

// removeNode removes an element from the linked list. O(1).
//
// Removing a middle node (B):
//
//	Before:   A <-> B <-> C
//	          ^     ^     ^
//	        prev   prev   prev
//	          |     |     |
//	        nil     A     B
//	After:    A <-> C
//
// Removing the head (A):
//
//	Before:   A <-> B <-> C
//	After:    B <-> C
//	          head = B
//
// Removing the tail (C):
//
//	Before:   A <-> B <-> C
//	After:    A <-> B
//	          tail = B
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
//
// Before:   (head)A <-> B <-> C(tail)
// After pushing D to front:
//
//	D <-> A <-> B <-> C
//	head = D
//
// If list was empty:
//
//	D (head & tail)
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
//
// Moving tail (D) to front:
//
//	Before:   A <-> B <-> C <-> D(tail)
//	After:    D(head) <-> A <-> B <-> C
//
// Moving middle node (B) to front:
//
//	Before:   A <-> B <-> C <-> D
//	After:    B(head) <-> A <-> C <-> D
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

	// Clear the map if its capacity is reasonable; otherwise, create a new one
	if len(s.logs) > 128 { // Threshold for creating a new map
		s.logs = make(map[string]*eventLogInfo, 64) // Reset with default capacity
	} else {
		clear(s.logs) // Retain the current map and clear its contents
	}

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

/*
	goos: windows
	goarch: amd64
	pkg: github.com/tekert/goetw/logsampler
	cpu: AMD Ryzen 7 5700X3D 8-Core Processor
	BenchmarkSamplers
	BenchmarkSamplers/DeduplicatingSampler (goroutine)
	BenchmarkSamplers/DeduplicatingSampler/SingleCore_16Keys
	BenchmarkSamplers/DeduplicatingSampler/SingleCore_16Keys-16              8264348               137.0 ns/op            46 B/op          3 allocs/op
	BenchmarkSamplers/DeduplicatingSampler/MultiCore_16Keys
	BenchmarkSamplers/DeduplicatingSampler/MultiCore_16Keys-16              38502307                29.53 ns/op           46 B/op          3 allocs/op
	BenchmarkSamplers/DeduplicatingSampler/SingleCore_1024Keys
	BenchmarkSamplers/DeduplicatingSampler/SingleCore_1024Keys-16            7106966               152.3 ns/op            54 B/op          3 allocs/op
	BenchmarkSamplers/DeduplicatingSampler/MultiCore_1024Keys
	BenchmarkSamplers/DeduplicatingSampler/MultiCore_1024Keys-16            36849237                31.70 ns/op           54 B/op          3 allocs/op

	BenchmarkSamplers/EventDrivenSampler (no goroutine)
	BenchmarkSamplers/EventDrivenSampler/SingleCore_16Keys
	BenchmarkSamplers/EventDrivenSampler/SingleCore_16Keys-16               13290795                91.78 ns/op            6 B/op          1 allocs/op
	BenchmarkSamplers/EventDrivenSampler/MultiCore_16Keys
	BenchmarkSamplers/EventDrivenSampler/MultiCore_16Keys-16                 5402576               211.4 ns/op             6 B/op          1 allocs/op
	BenchmarkSamplers/EventDrivenSampler/SingleCore_1024Keys
	BenchmarkSamplers/EventDrivenSampler/SingleCore_1024Keys-16             11229285               106.4 ns/op            13 B/op          1 allocs/op
	BenchmarkSamplers/EventDrivenSampler/MultiCore_1024Keys
	BenchmarkSamplers/EventDrivenSampler/MultiCore_1024Keys-16               5171302               222.9 ns/op            14 B/op          1 allocs/op
	PASS


	Running tool: C:\Program Files\Go\bin\go.exe test -benchmem -run=^$ -bench ^BenchmarkSamplers$ github.com/tekert/goetw/logsampler -v

goos: windows
goarch: amd64
pkg: github.com/tekert/goetw/logsampler
cpu: AMD Ryzen 7 5700X3D 8-Core Processor
BenchmarkSamplers
BenchmarkSamplers/DeduplicatingSampler
BenchmarkSamplers/DeduplicatingSampler/SingleCore_16Keys
BenchmarkSamplers/DeduplicatingSampler/SingleCore_16Keys-16
 9138038	       129.2 ns/op	      46 B/op	       3 allocs/op
BenchmarkSamplers/DeduplicatingSampler/MultiCore_16Keys
BenchmarkSamplers/DeduplicatingSampler/MultiCore_16Keys-16
33004570	        35.85 ns/op	      46 B/op	       3 allocs/op
BenchmarkSamplers/DeduplicatingSampler/SingleCore_1024Keys
BenchmarkSamplers/DeduplicatingSampler/SingleCore_1024Keys-16
 8197320	       145.2 ns/op	      54 B/op	       3 allocs/op
BenchmarkSamplers/DeduplicatingSampler/MultiCore_1024Keys
BenchmarkSamplers/DeduplicatingSampler/MultiCore_1024Keys-16
29245039	        40.64 ns/op	      54 B/op	       3 allocs/op

BenchmarkSamplers/EventDrivenSampler
BenchmarkSamplers/EventDrivenSampler/SingleCore_16Keys
BenchmarkSamplers/EventDrivenSampler/SingleCore_16Keys-16
14103327	        84.54 ns/op	       6 B/op	       1 allocs/op
BenchmarkSamplers/EventDrivenSampler/MultiCore_16Keys
BenchmarkSamplers/EventDrivenSampler/MultiCore_16Keys-16
 6484572	       184.4 ns/op	       6 B/op	       1 allocs/op
BenchmarkSamplers/EventDrivenSampler/SingleCore_1024Keys
BenchmarkSamplers/EventDrivenSampler/SingleCore_1024Keys-16
11823987	        99.94 ns/op	      13 B/op	       1 allocs/op
BenchmarkSamplers/EventDrivenSampler/MultiCore_1024Keys
BenchmarkSamplers/EventDrivenSampler/MultiCore_1024Keys-16
 5769141	       206.8 ns/op	      13 B/op	       1 allocs/op
PASS
*/
