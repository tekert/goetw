# High-Performance Log Sampler

This package provides concurrent-safe, high-performance log sampling strategies for Go applications. It is designed for use in hot paths where logging every event would be prohibitively expensive, such as high-frequency error reporting or verbose tracing.

The library is completely decoupled from any specific logging framework via a simple `SummaryReporter` interface, making it easy to integrate into any project.

## Core Concepts

### The `Sampler` Interface

All samplers implement this common interface:

-   `ShouldLog(key string, err error) bool`: The primary decision-making function. It returns `true` if the event should be logged and `false` if it should be suppressed.
-   `Flush()`: Triggers an immediate summary report of all currently suppressed logs.
-   `Close()`: Permanently shuts down the sampler, stopping any background tasks and performing a final flush.

### The `SummaryReporter` Interface

To remain logger-agnostic, the `DeduplicatingSampler` reports its summaries through this interface, which you must implement.

```go
type SummaryReporter interface {
    LogSummary(key string, suppressedCount int64)
}
```

This allows you to direct the summary output to `phuslu/log`, `zerolog`, the standard library logger, or any other system.

## Sampling Strategies

### 1. `DeduplicatingSampler` (Recommended)

This is a powerful and flexible sampler that combines time-based deduplication with optional rate-limiting. Its behavior is controlled by the `rate` parameter.

#### Pure Time-Based Deduplication (`rate <= 1`)

This is the default and most common use case for stopping log spam. It logs the **first** occurrence of an event for a given key, then suppresses all subsequent events for that key until the `window` duration has passed.

**Example:** Log an error once, then remain silent for 10 seconds.

````go
// Assumes 'myReporter' is your implementation of the SummaryReporter interface.
sampler := sampler.NewDeduplicatingSampler(1, 10*time.Second, myReporter)
````

#### Hybrid Sampling (`rate > 1`)

This mode combines the time window with 1-in-N sampling. It logs the first event and enters the quiet `window`. However, *within* that window, it will also log every Nth suppressed event, where N is the `rate`.

**Example:** Log the first error, then for the next 10 seconds, also log every 100th suppressed error.

````go
sampler := sampler.NewDeduplicatingSampler(100, 10*time.Second, myReporter)
````

### 2. `RateSampler`

This is a simpler, lightweight sampler that only performs 1-in-N sampling. It does not have a concept of a strict quiet period and does not produce summaries.

**Example:** Log 1 in every 1000 events.

````go
// The window is used to periodically reset the counter.
sampler := sampler.NewRateSampler(1000, 1*time.Minute)
````

## How to Use

Here is a complete example of integrating the `DeduplicatingSampler` with the standard library's `log` package.

#### Step 1: Implement a `SummaryReporter`

Create a simple struct that satisfies the `SummaryReporter` interface and directs output to your logger of choice.

````go
import (
    "log"
    "fmt"
)

type StdLibReporter struct{}

func (r *StdLibReporter) LogSummary(key string, suppressedCount int64) {
    log.Printf("Log Sampler Summary: key=%s suppressed_count=%d", key, suppressedCount)
}
````

#### Step 2: Create and Use the Sampler

Instantiate the sampler with your reporter and use it in your application's hot path.

````go
import (
    "errors"
    "time"
    "github.com/tekert/goetw/logsampler"
)

func main() {
    // Create a sampler that logs an error once, then suppresses for 5 seconds.
    reporter := &StdLibReporter{}
    logSampler := sampler.NewDeduplicatingSampler(1, 5*time.Second, reporter)
    defer logSampler.Close() // Ensures a final summary is flushed on exit.

    // Simulate a high-frequency error.
    for i := 0; i < 100; i++ {
        err := errors.New("database connection failed")
        if logSampler.ShouldLog("db-connection-error", err) {
            log.Printf("ERROR: %v", err)
        }
        time.Sleep(10 * time.Millisecond)
    }
}
````

#### Expected Output:

```
2025/08/15 23:00:00 ERROR: database connection failed
2025/08/15 23:00:05 Log Sampler Summary: key=db-connection-error suppressed_count=99
```
