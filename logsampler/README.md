 High-Performance Log Sampler

This package provides concurrent-safe, high-performance log sampling strategies for Go applications. It is designed for use in hot paths where logging every event would be prohibitively expensive, such as high-frequency error reporting or verbose tracing.

The library is completely decoupled from any specific logging framework via a simple `SummaryReporter` interface, making it easy to integrate into any project.

## Core Concepts

### The `Sampler` Interface

All samplers implement this common interface:

-   `ShouldLog(key string, err error) (bool, int64)`: The primary decision-making function. It returns `true` if the event should be logged. If `true`, it also returns the number of events that were suppressed since the last logged event for that key.
-   `Flush()`: Triggers an immediate summary report of all currently suppressed logs.
-   `Close()`: Permanently shuts down the sampler, performing a final flush. For samplers without background tasks, this is equivalent to `Flush()`.

### The `SummaryReporter` Interface

To remain logger-agnostic, the samplers report their summaries through this interface, which you must implement. This allows the sampler to report on suppressed logs for keys that have become inactive.

```go
type SummaryReporter interface {
    LogSummary(key string, suppressedCount int64)
}
```

This allows you to direct the summary output to `phuslu/log`, `zerolog`, the standard library logger, or any other system.

## Sampling Strategies

### 1. `EventDrivenSampler` (Recommended)

This is a powerful and flexible sampler that uses a time-based, **exponential backoff** strategy to suppress repeated log events. It **does not use background goroutines**.

When an event for a given key is logged, the sampler enters a "quiet window" during which subsequent events for the same key are suppressed. Each time an event is logged after a quiet window passes, the duration of the next quiet window increases, effectively reducing the log frequency for noisy, persistent events.

Instead of a background task, this sampler opportunistically checks for and reports summaries of "stale" keys each time `ShouldLog` is called. A key is considered stale if it has been inactive for the duration of `ResetInterval`.

Its behavior is controlled by the `BackoffConfig` struct:

```go
type BackoffConfig struct {
    InitialInterval time.Duration // The base quiet window after a log is emitted.
    MaxInterval     time.Duration // The maximum quiet window.
    Factor          float64       // The multiplication factor for the window (e.g., 2.0).
    // ResetInterval is the duration of inactivity after which the backoff window for a key is reset to InitialInterval.
    // This is also the duration used to determine if a key is "stale" and its summary should be flushed.
    ResetInterval time.Duration
}
```

**Example:** Log an error, then suppress for 1s. If another occurs after 1s, log it and suppress for 2s, then 4s, and so on, up to a maximum of 1 minute. If the error is silent for 5 minutes, the backoff resets to 1s. If any other key is logged after this 5-minute period, the summary for the original stale key will be reported.

````go
// Assumes 'myReporter' is your implementation of the SummaryReporter interface.
config := logsampler.BackoffConfig{
    InitialInterval: 1 * time.Second,
    MaxInterval:     1 * time.Minute,
    Factor:          2.0,
    ResetInterval:   5 * time.Minute, // Required for stale key reporting
}
// Note: NewEventDrivenSampler requires a non-nil reporter.
sampler := logsampler.NewEventDrivenSampler(config, myReporter)
defer sampler.Close() // Ensures a final summary is flushed on exit.
````

### 2. `DeduplicatingSampler` (Legacy)

**Deprecated:** This sampler uses a background goroutine. Use `EventDrivenSampler` for a goroutine-free alternative.

This sampler has the same exponential backoff logic as `EventDrivenSampler` but uses a background goroutine and a `time.Ticker` to periodically scan for and report summaries of inactive keys. While effective, it introduces a hidden background task that the user must manage by calling `Close()`.

This is a powerful and flexible sampler that uses a time-based, **exponential backoff** strategy to suppress repeated log events. When an event for a given key is logged, the sampler enters a "quiet window" during which subsequent events for the same key are suppressed. Each time an event is logged after a quiet window passes, the duration of the next quiet window increases, effectively reducing the log frequency for noisy, persistent events.

Its behavior is controlled by the `BackoffConfig` struct:

```go
type BackoffConfig struct {
    InitialInterval time.Duration // The base quiet window after a log is emitted.
    MaxInterval     time.Duration // The maximum quiet window.
    Factor          float64       // The multiplication factor for the window (e.g., 2.0).
    // ResetInterval is the duration of inactivity after which the backoff window for a key is reset to InitialInterval.
    // If zero, the backoff window never resets.
    ResetInterval time.Duration
}
```

**Example:** Log an error, then suppress for 1s. If another occurs after 1s, log it and suppress for 2s, then 4s, and so on, up to a maximum of 1 minute. If the error is silent for 5 minutes, the backoff resets to 1s.

````go
// Assumes 'myReporter' is your implementation of the SummaryReporter interface.
config := logsampler.BackoffConfig{
    InitialInterval: 1 * time.Second,
    MaxInterval:     1 * time.Minute,
    Factor:          2.0,
    ResetInterval:   5 * time.Minute,
}
sampler := logsampler.NewDeduplicatingSampler(config, myReporter)
````

The sampler automatically runs a background task to report summaries for keys that have become inactive, preventing lost information and memory leaks.

### 3. `RateSampler`

This is a simpler, lightweight sampler that only performs 1-in-N sampling. It does not have a concept of a strict quiet period and does not produce summaries.

**Example:** Log 1 in every 1000 events.

````go
// The window is used to periodically reset the counter.
sampler := sampler.NewRateSampler(1000, 1*time.Minute)
````

## How to Use

The integration pattern is the same for all samplers. The following example uses the recommended `EventDrivenSampler`.

### Example: Integration with a Structured Logger (`phuslu/log`)

The best practice for a clean API is to wrap your logger in a custom struct. This allows you to create dedicated methods like `SampledError` that hide the sampling logic from the call site.

#### Step 1: Implement a `SummaryReporter`

Create a reporter that uses your structured logger to emit summary events.

````go
import (
    "github.com/phuslu/log"
)

// PLogReporter implements the SummaryReporter interface using phuslu/log.
type PLogReporter struct {
    Logger *log.Logger
}

func (r *PLogReporter) LogSummary(key string, suppressedCount int64) {
    r.Logger.Info().
        Str("sampler_key", key).
        Int64("suppressed_count", suppressedCount).
        Msg("Log sampler summary")
}
````

#### Step 2: Create a `SampledLogger` Wrapper

Define a struct that embeds your logger and holds the sampler.

````go
import (
    "github.com/tekert/goetw/logsampler"
    "github.com/phuslu/log"
)

// SampledLogger wraps a phuslu/log logger to provide sampling methods.
type SampledLogger struct {
    *log.Logger // Embed the original logger to keep all its methods.
    sampler     logsampler.Sampler
}

// NewSampledLogger creates a new logger with sampling capabilities.
func NewSampledLogger(logger *log.Logger, sampler logsampler.Sampler) *SampledLogger {
    return &SampledLogger{
        Logger:  logger,
        sampler: sampler,
    }
}

// SampledError logs an error message, but only if the sampler allows it.
// The 'key' is used to group similar events for deduplication.
func (l *SampledLogger) SampledError(key string, err error, msg string) {
    if should, suppressed := l.sampler.ShouldLog(key, err); should {
        l.Logger.Error().
            Err(err).
            Int64("suppressed_count", suppressed).
            Msg(msg)
    }
}
````

#### Step 3: Put It All Together

Use your new `SampledLogger` in your application.

````go
import (
    "errors"
    "os"
    "time"
    "github.com/tekert/goetw/logsampler"
    "github.com/phuslu/log"
)

func main() {
    // 1. Configure the base structured logger.
    baseLogger := &log.Logger{
        Level:  log.InfoLevel,
        Writer: &log.IOWriter{Writer: os.Stdout},
    }

    // 2. Create the sampler with a reporter that uses the base logger.
    reporter := &PLogReporter{Logger: baseLogger}
    config := logsampler.BackoffConfig{
        InitialInterval: 5 * time.Second,
        MaxInterval:     1 * time.Minute,
        Factor:          1.5,
        ResetInterval:   10 * time.Minute,
    }
    logSampler := logsampler.NewEventDrivenSampler(config, reporter)
    defer logSampler.Close()

    // 3. Create the wrapped SampledLogger.
    logger := NewSampledLogger(baseLogger, logSampler)

    // 4. Use the simple, clean API in your hot path.
    // Simulate a burst of 100 errors in 1 second.
    for i := 0; i < 100; i++ {
        err := errors.New("database connection failed")
        // The call is now a simple, single line.
        logger.SampledError("db-connection-error", err, "Database connection failed repeatedly")
        time.Sleep(10 * time.Millisecond)
    }
    
    // On exit, logSampler.Close() will be called, and the reporter will log
    // a summary for the 99 events that were suppressed.
}
````

#### Expected JSON Output:

```json
{"level":"error","time":"2025-08-26T10:00:00.000Z","error":"database connection failed","suppressed_count":0,"message":"Database connection failed repeatedly"}
{"level":"info","time":"2025-08-26T10:00:01.000Z","sampler_key":"db-connection-error","suppressed_count":99,"message":"Log sampler summary"}
```

[See the our implementation in log.go](../etw/log.go)