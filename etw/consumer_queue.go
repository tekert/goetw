//go:build windows

package etw

import (
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// EventBuffer just batches events before sending them to the output channel.
// The sweet spot is 20 events per batch and 200ms timeout.
// if not enough events are queued, it will flush the buffer after 200ms.

// It's better to define your own EventCallback either way.
// using batches as payloads still has 6% overhead Total compared to callback.

// When sending pointers (8 bytes) one by one trough a channel:
// In benchmarks performs 16% worse overall (a lot) for high concurrent events.
//
// While using only 1 callback/ProcessTrace thread: (1 trace only):
// channels overhead comes from runtime.chansed(2.2%), runtime.send(1.2%),
// runtime.schedule(3,14%), runtime.wakup (6,6%) (cgo stdcall1 and stdcall2),
// runtime.mallocgc (1,5%) and runtime.lock2(1,54%)
// for a total of ~16% of the time of the whole process is spent on this.
// In the end, don't use go channels for small playloads.

// Used to store events in a buffer before sending them to the output channel.
// This is used to batch events and avoid sending them one by one.
// Wich is more efficient.
type EventBuffer struct {
	sync.Mutex

	// The maximum number of events that can be stored in the batch.
	// This the ammout of events received before flushing the buffer.
	// Default: 20
	BatchSize int

	// The maximum time to wait before flushing the buffer.
	// Used when less than BatchSize events are queued.
	// Default: 200ms
	Timeout time.Duration

	// The default callback [DefaultEventCallback] outputs parsed events to this channel.
	// This channel can be used to consume events in a non-blocking way.
	//
	// The events are batched by size = [Consumer.EventsConfig.BatchSize]
	// use [Consumer.ProcessEvents] for easier consumption (no need to Release events).
	//
	// If consuming directly from this channel, remember to Event.Release()
	// when done with the event, increases performance
	Channel chan []*Event

	// Queues
	skippableEvents    []*Event
	nonskippableEvents []*Event

	// Output channel
	skipped   *atomic.Uint64
	closed    atomic.Bool
	timer     *time.Timer // flush timer
	closeOnce sync.Once   // Ensures the channel is closed exactly once.
}

func NewEventBuffer() *EventBuffer {
	return &EventBuffer{
		skippableEvents:    make([]*Event, 0, 512),
		nonskippableEvents: make([]*Event, 0, 512),
		Timeout:            200 * time.Millisecond,
		BatchSize:          20,
		Channel:            make(chan []*Event, 10),
	}
}

// Try to acquire lock with timeout
func (e *EventBuffer) tryLockWithTimeout(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if e.TryLock() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// Flushes and then closes the channel
// if the channel is blocked, try to acquire lock with timeout.
// if we can't acquire the lock, just close the channel without flush.
//
// This is executed from the client goroutine from [Consumer.close]
func (e *EventBuffer) close() error {
	// This logic will now only run once.
	e.closeOnce.Do(func() {
		defer func() {
			// Recover from a panic if the channel is closed externally
			if r := recover(); r != nil {
				conlog.Warn().Msgf("Recovered from panic while closing Events channel: %v", r)
			}
		}()

		e.closed.Store(true) // Mark as closed immediately.

		// Try graceful shutdown first, timeout after 500ms
		if e.tryLockWithTimeout(500 * time.Millisecond) {
			defer e.Unlock()

			if e.timer != nil {
				e.timer.Stop()
				e.timer = nil
			}

			// Safe flush while we have the lock
			e.flush()
		}

		// Single thread that passed closes channel
		close(e.Channel)
		conlog.Info().Msg("Events channel closed.")
	})
	return nil
}

// flush processes and dispatches both skippable
// and non-skippable events through the Events channel.
func (e *EventBuffer) flush() {
	// Process skippable events if any
	if len(e.skippableEvents) > 0 {
		// copy slice (it's going to be reseted after sending it)
		batch := slices.Clone(e.skippableEvents)
		select {
		case e.Channel <- batch:
		default:
			// Channel full, increment skip counter
			e.skipped.Add(uint64(len(batch)))
			for _, e := range batch {
				e.Release()
			}
		}
		e.skippableEvents = e.skippableEvents[:0]
	}

	// Process non-skippable events - blocks if channel is full
	if len(e.nonskippableEvents) > 0 {
		batch := slices.Clone(e.nonskippableEvents)
		e.Channel <- batch
		e.nonskippableEvents = e.nonskippableEvents[:0]
	}
}

//go:inline
func (e *EventBuffer) pending() int {
	return len(e.skippableEvents) + len(e.nonskippableEvents)
}

// Blocks if channel buffer is full for non skipable events.
//
//	(this is executed from the etw.ProcessTrace or client goroutine)
func (e *EventBuffer) Send(event *Event) {
	e.Lock()
	defer e.Unlock()

	if e.closed.Load() {
		event.Release()
		return
	}

	// Add event to queue
	if event.Flags.Skippable {
		e.skippableEvents = append(e.skippableEvents, event)
	} else {
		e.nonskippableEvents = append(e.nonskippableEvents, event)
	}

	// Flush if events queues reached maximum size
	if e.pending() >= e.BatchSize {
		// Stop timer since we are force flushing
		if e.timer != nil {
			e.timer.Stop()
			e.timer = nil
		}
		e.flush() // may block if channel is full
		return
	}

	// Start timer to flush queue if not enough events come in.
	if e.timer == nil {
		e.timer = time.AfterFunc(e.Timeout, func() {
			e.Lock()
			// if timer is still active, flush events
			if e.timer != nil && !e.closed.Load() {
				e.flush()
			}
			e.timer = nil
			e.Unlock()
		})
	}
}
