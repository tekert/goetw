package logsampler_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	sampler "github.com/tekert/goetw/logsampler"
)

func TestDeduplicatingSampler(t *testing.T) {
	t.Run("LogsFirstAndSuppressesSecond", func(t *testing.T) {
		cfg := sampler.BackoffConfig{InitialInterval: 100 * time.Millisecond}
		s := sampler.NewDeduplicatingSampler(cfg, nil)
		defer s.Close()

		if should, _ := s.ShouldLog("key1", nil); !should {
			t.Fatal("First log should pass")
		}
		if should, _ := s.ShouldLog("key1", nil); should {
			t.Fatal("Second log within window should be suppressed")
		}
	})

	t.Run("LogsAfterWindowAndReportsSuppressed", func(t *testing.T) {
		cfg := sampler.BackoffConfig{InitialInterval: 100 * time.Millisecond}
		s := sampler.NewDeduplicatingSampler(cfg, nil)
		defer s.Close()

		s.ShouldLog("key1", nil) // First log
		for range 5 {
			s.ShouldLog("key1", nil) // Suppress 5 times
		}

		time.Sleep(110 * time.Millisecond)

		should, suppressed := s.ShouldLog("key1", nil)
		if !should {
			t.Fatal("Log after window should pass")
		}
		if suppressed != 5 {
			t.Fatalf("Expected to report 5 suppressed logs, got %d", suppressed)
		}
	})

	t.Run("AppliesExponentialBackoff", func(t *testing.T) {
		cfg := sampler.BackoffConfig{
			InitialInterval: 50 * time.Millisecond,
			MaxInterval:     500 * time.Millisecond,
			Factor:          2.0,
		}
		s := sampler.NewDeduplicatingSampler(cfg, nil)
		defer s.Close()

		// 1. Initial log. A 50ms quiet window is now active.
		//    The *next* window is calculated to be 100ms.
		if should, _ := s.ShouldLog("key1", nil); !should {
			t.Fatal("Initial log should always pass")
		}

		// 2. Wait 40ms. This is < 50ms. Should be suppressed.
		time.Sleep(40 * time.Millisecond)
		if should, _ := s.ShouldLog("key1", nil); should {
			t.Fatal("Should have been suppressed by 50ms window")
		}

		// 3. Wait another 20ms (total time elapsed ~60ms). This is > 50ms. Should log.
		//    A 100ms quiet window is now active.
		time.Sleep(20 * time.Millisecond)
		if should, _ := s.ShouldLog("key1", nil); !should {
			t.Fatal("Should have logged after 50ms window passed")
		}

		// 4. Wait 80ms. This is < 100ms. Should be suppressed.
		time.Sleep(80 * time.Millisecond)
		if should, _ := s.ShouldLog("key1", nil); should {
			t.Fatal("Should have been suppressed by 100ms backoff window")
		}

		// 5. Wait another 30ms (total time elapsed ~110ms). This is > 100ms. Should log.
		time.Sleep(30 * time.Millisecond)
		if should, _ := s.ShouldLog("key1", nil); !should {
			t.Fatal("Should have logged after 100ms window passed")
		}
	})

	t.Run("ResetsBackoffAfterInactivity", func(t *testing.T) {
		cfg := sampler.BackoffConfig{
			InitialInterval: 50 * time.Millisecond,
			MaxInterval:     200 * time.Millisecond,
			Factor:          2.0,
			ResetInterval:   300 * time.Millisecond, // Reset after 300ms of silence.
		}
		s := sampler.NewDeduplicatingSampler(cfg, nil)
		defer s.Close()

		// 1. Log a few times to increase the backoff window to its max.
		s.ShouldLog("key1", nil) // Window is now 50ms
		time.Sleep(60 * time.Millisecond)
		s.ShouldLog("key1", nil) // Window is now 100ms
		time.Sleep(110 * time.Millisecond)
		s.ShouldLog("key1", nil) // Window is now 200ms (max)

		// 2. Wait for a period longer than the ResetInterval.
		time.Sleep(310 * time.Millisecond)

		// 3. This log should now pass immediately because the backoff has been reset.
		if should, suppressed := s.ShouldLog("key1", nil); !should {
			t.Fatal("Log after reset interval should have passed")
		} else if suppressed != 0 {
			t.Fatalf("Expected 0 suppressed events after a quiet period, got %d", suppressed)
		}

		// 4. The active window should have been reset to the InitialInterval (50ms).
		//    A log after just 30ms should now be suppressed.
		time.Sleep(30 * time.Millisecond)
		if should, _ := s.ShouldLog("key1", nil); should {
			t.Fatal("Should have been suppressed by the reset (initial) window")
		}
	})
}

func TestDeduplicatingSampler_SteadyRate(t *testing.T) {
	t.Run("SingleGoroutine_SteadyRate", func(t *testing.T) {
		t.Parallel()
		cfg := sampler.BackoffConfig{
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     1 * time.Second,
			Factor:          2.0,
		}
		s := sampler.NewDeduplicatingSampler(cfg, nil)
		defer s.Close()

		eventRate := 10 * time.Millisecond // 100 events/sec
		testDuration := 800 * time.Millisecond

		ticker := time.NewTicker(eventRate)
		defer ticker.Stop()
		done := time.After(testDuration)

		var suppressedCounts []int64
		var lastSuppressed int64

		for {
			select {
			case <-ticker.C:
				if should, suppressed := s.ShouldLog("steady-key", nil); should {
					suppressedCounts = append(suppressedCounts, suppressed)
					// The first count is 0, all subsequent counts must be greater than the last.
					if suppressed > 0 && suppressed <= lastSuppressed {
						t.Fatalf("Suppressed count should be increasing, but got %d after %d. All counts: %v",
							suppressed, lastSuppressed, suppressedCounts)
					}
					lastSuppressed = suppressed
				}
			case <-done:
				// The first log has a count of 0. We expect at least 2 more logs after that.
				if len(suppressedCounts) < 3 {
					t.Fatalf("Expected at least 3 logs during the test, but got %d", len(suppressedCounts))
				}
				return
			}
		}
	})

	t.Run("MultiGoroutine_MultiKey_SteadyRate", func(t *testing.T) {
		t.Parallel()
		cfg := sampler.BackoffConfig{
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     1 * time.Second,
			Factor:          2.0,
		}
		s := sampler.NewDeduplicatingSampler(cfg, nil)
		defer s.Close()

		numGoroutines := 4
		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		for i := range numGoroutines {
			go func(id int) {
				defer wg.Done()
				key := fmt.Sprintf("steady-key-%d", id)
				eventRate := 10 * time.Millisecond
				testDuration := 800 * time.Millisecond

				ticker := time.NewTicker(eventRate)
				defer ticker.Stop()
				done := time.After(testDuration)

				for {
					select {
					case <-ticker.C:
						// We don't need to check the output here, just that it runs
						// without deadlocking or panicking, proving key isolation.
						s.ShouldLog(key, nil)
					case <-done:
						return
					}
				}
			}(i)
		}
		wg.Wait()
	})
}

// mockReporter captures summary calls for testing.
type mockReporter struct {
	mu        sync.Mutex
	summaries map[string]int64
}

func newMockReporter() *mockReporter {
	return &mockReporter{
		summaries: make(map[string]int64),
	}
}

func (r *mockReporter) LogSummary(key string, suppressedCount int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.summaries[key] = suppressedCount
}

func (r *mockReporter) getSummary(key string) (int64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	val, ok := r.summaries[key]
	return val, ok
}

// mockClock allows deterministic time control in tests.
type mockClock struct {
	currentTime time.Time
}

func (c *mockClock) Now() time.Time {
	return c.currentTime
}

func (c *mockClock) Advance(d time.Duration) {
	c.currentTime = c.currentTime.Add(d)
}

func newTestEventDrivenSampler(config sampler.BackoffConfig,
	reporter sampler.SummaryReporter) (*sampler.EventDrivenSampler, *mockClock) {

	s := sampler.NewEventDrivenSampler(config, reporter)
	clock := &mockClock{currentTime: time.Now()}
	s.SetClock(clock)
	return s, clock
}

func TestEventDrivenSampler(t *testing.T) {

	t.Run("SingleLogEventTriggersStaleCleanup", func(t *testing.T) {
		reporter := newMockReporter()
		cfg := sampler.BackoffConfig{
			InitialInterval: 10 * time.Millisecond,
			MaxInterval:     100 * time.Millisecond,
			Factor:          2.0,
			ResetInterval:   50 * time.Millisecond,
		}
		s, clock := newTestEventDrivenSampler(cfg, reporter)
		defer s.Close()

		// Generate some logs for a key to build up suppressed count
		firstKey := "key-to-become-stale"
		s.ShouldLog(firstKey, nil) // First log - always passes

		// Log several times to trigger exponential backoff and build up suppressed count
		for i := 0; i < 10; i++ {
			clock.Advance(1 * time.Millisecond)
			s.ShouldLog(firstKey, nil) // These will be suppressed
		}

		// Verify we have suppressed logs but no summary yet
		if count, ok := reporter.getSummary(firstKey); ok {
			t.Fatalf("Expected no summary yet for %s, but got count %d", firstKey, count)
		}

		// Now advance the clock beyond the reset interval to make the key stale
		clock.Advance(60 * time.Millisecond)

		// Force cleanupInterval number of operations to ensure cleanup happens
		for i := range 65 {
			secondKey := fmt.Sprintf("trigger-key-%d", i)
			s.ShouldLog(secondKey, nil)
		}

		// Verify the stale key's suppressed logs were reported
		if count, ok := reporter.getSummary(firstKey); !ok {
			t.Fatal("Expected summary for stale key to be reported after a single new log event")
		} else if count != 10 {
			t.Fatalf("Expected suppressed count to be 10, got %d", count)
		}

		// Now log the first key again - it should be treated as a new log (reset)
		should, suppressed := s.ShouldLog(firstKey, nil)
		if !should {
			t.Fatal("Log after reset interval should pass")
		}
		if suppressed != 0 {
			t.Fatalf("Expected suppressed count to be 0 after reset, got %d", suppressed)
		}
	})

	t.Run("LogsFirstAndSuppressesSecond", func(t *testing.T) {
		reporter := newMockReporter()
		cfg := sampler.BackoffConfig{InitialInterval: 100 * time.Millisecond}
		s, _ := newTestEventDrivenSampler(cfg, reporter)
		defer s.Close()

		if should, _ := s.ShouldLog("key1", nil); !should {
			t.Fatal("First log should pass")
		}
		if should, _ := s.ShouldLog("key1", nil); should {
			t.Fatal("Second log within window should be suppressed")
		}
	})

	t.Run("LogsAfterWindowAndReportsSuppressed", func(t *testing.T) {
		reporter := newMockReporter()
		cfg := sampler.BackoffConfig{InitialInterval: 100 * time.Millisecond}
		s, clock := newTestEventDrivenSampler(cfg, reporter)
		defer s.Close()

		s.ShouldLog("key1", nil) // First log
		for range 5 {
			s.ShouldLog("key1", nil) // Suppress 5 times
		}

		clock.Advance(110 * time.Millisecond)

		should, suppressed := s.ShouldLog("key1", nil)
		if !should {
			t.Fatal("Log after window should pass")
		}
		if suppressed != 5 {
			t.Fatalf("Expected to report 5 suppressed logs, got %d", suppressed)
		}
	})

	t.Run("AppliesExponentialBackoff", func(t *testing.T) {
		reporter := newMockReporter()
		cfg := sampler.BackoffConfig{
			InitialInterval: 50 * time.Millisecond,
			MaxInterval:     500 * time.Millisecond,
			Factor:          2.0,
		}
		s, clock := newTestEventDrivenSampler(cfg, reporter)
		defer s.Close()

		// Initial log
		if should, _ := s.ShouldLog("key1", nil); !should {
			t.Fatal("Initial log should always pass")
		}

		// Advance time by 40ms. This is < 50ms. Should be suppressed.
		clock.Advance(40 * time.Millisecond)
		if should, _ := s.ShouldLog("key1", nil); should {
			t.Fatal("Should have been suppressed by 50ms window")
		}

		// Advance another 20ms (total 60ms). This is > 50ms. Should log.
		clock.Advance(20 * time.Millisecond)
		if should, _ := s.ShouldLog("key1", nil); !should {
			t.Fatal("Should have logged after 50ms window passed")
		}

		// Advance 80ms. This is < 100ms (new backoff window). Should be suppressed.
		clock.Advance(80 * time.Millisecond)
		if should, _ := s.ShouldLog("key1", nil); should {
			t.Fatal("Should have been suppressed by 100ms backoff window")
		}
	})

	t.Run("OpportunisticallyFlushesStaleKeys", func(t *testing.T) {
		reporter := newMockReporter()
		cfg := sampler.BackoffConfig{
			InitialInterval: 10 * time.Millisecond,
			ResetInterval:   50 * time.Millisecond,
		}
		s, clock := newTestEventDrivenSampler(cfg, reporter)
		defer s.Close()

		// Use the same key to ensure it's in the same shard
		baseKey := "stale-test"

		// Log and suppress baseKey once
		s.ShouldLog(baseKey, nil)
		clock.Advance(1 * time.Millisecond)
		s.ShouldLog(baseKey, nil) // Suppressed count is now 1

		// Advance time for baseKey to become stale
		clock.Advance(60 * time.Millisecond)

		// Log the same key again - this should trigger stale flushing and reset
		should, suppressed := s.ShouldLog(baseKey, nil)
		if !should {
			t.Fatal("Log after reset interval should have passed")
		}
		if suppressed != 1 {
			t.Fatalf("Expected suppressed count to be 1, got %d", suppressed)
		}
	})

	t.Run("FlushClearsAllSuppressedLogs", func(t *testing.T) {
		reporter := newMockReporter()
		cfg := sampler.BackoffConfig{InitialInterval: 1 * time.Second}
		s, clock := newTestEventDrivenSampler(cfg, reporter)

		s.ShouldLog("key1", nil) // Log once
		s.ShouldLog("key1", nil) // Suppress
		s.ShouldLog("key2", nil) // Log once
		s.ShouldLog("key2", nil) // Suppress
		s.ShouldLog("key2", nil) // Suppress

		s.Flush()

		if count, ok := reporter.getSummary("key1"); !ok || count != 1 {
			t.Fatalf("Expected flushed count for key1 to be 1, got %d", count)
		}
		if count, ok := reporter.getSummary("key2"); !ok || count != 2 {
			t.Fatalf("Expected flushed count for key2 to be 2, got %d", count)
		}

		// After flush, logging again should start with 0 suppressed
		s.ShouldLog("key1", nil)
		clock.Advance(1 * time.Millisecond)
		should, suppressed := s.ShouldLog("key1", nil)
		if should {
			t.Fatal("Should have been suppressed by new window")
		}
		if suppressed != 0 {
			t.Fatalf("Suppressed count should be 0 after a flush, got %d", suppressed)
		}
	})
}

func BenchmarkSamplers(b *testing.B) {
	reporter := newMockReporter()
	baseConfig := sampler.BackoffConfig{
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     1 * time.Second,
		Factor:          2.0,
		ResetInterval:   5 * time.Second,
	}

	runBenchmarks := func(b *testing.B, s sampler.Sampler, keyspace int) {
		b.Run(fmt.Sprintf("SingleCore_%dKeys", keyspace), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				s.ShouldLog(fmt.Sprintf("key-%d", i%keyspace), nil)
			}
		})

		b.Run(fmt.Sprintf("MultiCore_%dKeys", keyspace), func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					s.ShouldLog(fmt.Sprintf("key-%d", i%keyspace), nil)
					i++
				}
			})
		})
	}

	b.Run("DeduplicatingSampler", func(b *testing.B) {
		s := sampler.NewDeduplicatingSampler(baseConfig, reporter)
		defer s.Close()
		b.ResetTimer()
		runBenchmarks(b, s, 16)
		runBenchmarks(b, s, 1024)
	})

	b.Run("EventDrivenSampler", func(b *testing.B) {
		s := sampler.NewEventDrivenSampler(baseConfig, reporter)
		defer s.Close()
		b.ResetTimer()
		runBenchmarks(b, s, 16)
		runBenchmarks(b, s, 1024)
	})
}
