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
