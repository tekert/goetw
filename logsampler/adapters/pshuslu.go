// Package log provides a high-performance, sampled logger built on top of
// phuslu/log and the goetw/logsampler.
package adapters

import (
	"hash/maphash"
	"strconv"
	"sync/atomic"

	"github.com/tekert/goetw/logsampler"

	plog "github.com/phuslu/log"
)

// A package-level seed for maphash ensures that hashes are consistent.
var hashSeed = maphash.MakeSeed()

// Sampler is an alias for the logsampler interface.
type Sampler = logsampler.Sampler

// SummaryReporter is an adapter that implements the logsampler.SummaryReporter
// interface using a phuslu/log logger.
type SummaryReporter struct {
	Logger *plog.Logger
}

// LogSummary logs a sampler summary report.
func (r *SummaryReporter) LogSummary(key string, suppressedCount int64) {
	r.Logger.Info().
		Str("samplerKey", key).
		Int64("suppressedCount", suppressedCount).
		Msg("log sampler summary")
}

// SampledLogger extends plog.Logger with methods for high-performance sampling.
type SampledLogger struct {
	*plog.Logger
	Sampler Sampler
}

// NewSampledLogger creates a new logger with sampling capabilities.
func NewSampledLogger(baseLogger *plog.Logger, sampler Sampler) *SampledLogger {
	return &SampledLogger{
		Logger:  baseLogger,
		Sampler: sampler,
	}
}

// Sampled is the generic implementation for all sampled log calls.
func (l *SampledLogger) Sampled(level plog.Level, key string, useErrSig bool, err ...error) *plog.Entry {
	// 1. If the log level is too high, we exit immediately with zero allocations.
	if plog.Level(atomic.LoadUint32((*uint32)(&l.Logger.Level))) > level {
		return nil
	}

	var e error
	if len(err) > 0 {
		e = err[0]
	}

	// 2. If using error signature, create a more granular key.
	if useErrSig && e != nil {
		// Use the highly optimized maphash on the entire error string.
		var h maphash.Hash
		h.SetSeed(hashSeed)
		h.WriteString(e.Error())

		// Efficiently build key using a byte buffer and strconv
		var buf [128]byte
		b := buf[:0]
		b = append(b, key...)
		b = append(b, ':')
		b = strconv.AppendUint(b, h.Sum64(), 16)
		key = string(b)
	}

	// 3. Consult the sampler to see if we should log.
	if l.Sampler != nil {
		if shouldLog, suppressedCount := l.Sampler.ShouldLog(key, e); shouldLog {
			entry := l.Logger.WithLevel(level)
			if suppressedCount > 0 {
				entry.Int64("suppressedCount", suppressedCount)
			}
			if e != nil {
				entry.Err(e)
			}
			return entry
		}
	} else {
		// No sampler configured, log directly.
		entry := l.Logger.WithLevel(level)
		if e != nil {
			entry.Err(e)
		}
		return entry
	}

	// The sampler decided to suppress this log.
	return nil
}

// SampledError starts a new sampled log event with Error level.
func (l *SampledLogger) SampledError(key string) *plog.Entry {
	return l.Sampled(plog.ErrorLevel, key, false)
}

// SampledErrorWithErrSig is like SampledError but uses the error's content for sampling.
func (l *SampledLogger) SampledErrorWithErrSig(key string, err ...error) *plog.Entry {
	return l.Sampled(plog.ErrorLevel, key, true, err...)
}

// SampledWarn starts a new sampled log event with Warn level.
func (l *SampledLogger) SampledWarn(key string) *plog.Entry {
	return l.Sampled(plog.WarnLevel, key, false)
}

// SampledWarnWithErrSig is like SampledWarn but uses the error's content for sampling.
func (l *SampledLogger) SampledWarnWithErrSig(key string, err ...error) *plog.Entry {
	return l.Sampled(plog.WarnLevel, key, true, err...)
}

// SampledTrace starts a new sampled log event with Trace level.
func (l *SampledLogger) SampledTrace(key string) *plog.Entry {
	return l.Sampled(plog.TraceLevel, key, false)
}

// SampledTraceWithErrSig is like SampledTrace but uses the error's content for sampling.
func (l *SampledLogger) SampledTraceWithErrSig(key string, err ...error) *plog.Entry {
	return l.Sampled(plog.TraceLevel, key, true, err...)
}
