/*
Package sampler provides high-performance, concurrent-safe log sampling strategies.
It is designed for use in hot paths of applications where logging every event would
be prohibitively expensive, such as high-frequency error reporting or verbose tracing.
*/
package logsampler

import (
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
