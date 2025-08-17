//go:build windows

// Package etw provides simple logging using phuslu/log library
// and a high-performance sampler for hot paths.

package etw

import (
	"hash/maphash" // Import maphash
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/tekert/goetw/logsampler"

	plog "github.com/phuslu/log"
)

// A package-level seed for maphash ensures that hashes are consistent
// for the lifetime of the application.
var hashSeed = maphash.MakeSeed()

// plogSummaryReporter is an adapter that implements the sampler.SummaryReporter
// interface using a phuslu/log logger.
type plogSummaryReporter struct {
	logger *plog.Logger
}

// LogSummary logs a sampler summary report using the configured plog.Logger.
func (r *plogSummaryReporter) LogSummary(key string, suppressedCount int64) {
	r.logger.Info().
		Str("samplerKey", key).
		Int64("suppressedCount", suppressedCount).
		Msg("log sampler summary")
}

// LoggerName defines the name of a logger for configuration.
type LoggerName string

// Available logger names. Use these as keys when configuring log levels.
const (
	ConsumerLogger LoggerName = "consumer"
	SessionLogger  LoggerName = "session"
	DefaultLogger  LoggerName = "default"
)

// Sampler is an alias for the internal sampler interface.
type Sampler = logsampler.Sampler

// SampledLogger extends plog.Logger with methods for high-performance sampling.
type SampledLogger struct {
	*plog.Logger
	sampler Sampler
}

// sampled is the private generic implementation for all sampled log calls.
// It performs the level check, optional error signature hashing, and sampler query
// before creating a log entry, ensuring maximum performance on suppressed calls.
func (l *SampledLogger) sampled(level plog.Level, key string, useErrSig bool, err ...error) *plog.Entry {
	// 1. High-performance level check. If the log level is too high, we exit
	// immediately with zero allocations.
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
	if l.sampler != nil {
		if shouldLog, suppressedCount := l.sampler.ShouldLog(key, e); shouldLog {
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
	return l.sampled(plog.ErrorLevel, key, false)
}

// SampledErrorWithErrSig is like SampledError but uses the error's content for sampling.
// You dont need to call .Err() on the returned entry, it's done automatically.
func (l *SampledLogger) SampledErrorWithErrSig(key string, err ...error) *plog.Entry {
	return l.sampled(plog.ErrorLevel, key, true, err...)
}

// SampledWarn starts a new sampled log event with Warn level.
func (l *SampledLogger) SampledWarn(key string) *plog.Entry {
	return l.sampled(plog.WarnLevel, key, false)
}

// SampledWarnWithErrSig is like SampledWarn but uses the error's content for sampling.
// You dont need to call .Err() on the returned entry, it's done automatically.
func (l *SampledLogger) SampledWarnWithErrSig(key string, err ...error) *plog.Entry {
	return l.sampled(plog.WarnLevel, key, true, err...)
}

// SampledTrace starts a new sampled log event with Trace level.
func (l *SampledLogger) SampledTrace(key string) *plog.Entry {
	return l.sampled(plog.TraceLevel, key, false)
}

// SampledTraceWithErrSig is like SampledTrace but uses the error's content for sampling.
// You dont need to call .Err() on the returned entry, it's done automatically.
func (l *SampledLogger) SampledTraceWithErrSig(key string, err ...error) *plog.Entry {
	return l.sampled(plog.TraceLevel, key, true, err...)
}

// LoggerManager manages all three loggers
type LoggerManager struct {
	writer  plog.Writer
	sampler Sampler
	loggers map[LoggerName]*plog.Logger // Use a map for scalability

	// Keep direct references for convenience and internal use
	conlog *plog.Logger
	seslog *plog.Logger
	deflog *plog.Logger
}

// Global logger manager and convenient logger variables
var (
	loggerManager *LoggerManager
	conlog        *SampledLogger // Consumer hot path
	seslog        *plog.Logger   // Session operations
	log           *plog.Logger   // Default/everything else
)

// Initialize loggers on package import
func init() {
	loggerManager = NewLoggerManager()
	conlog = &SampledLogger{
		Logger:  loggerManager.loggers[ConsumerLogger],
		sampler: loggerManager.sampler,
	}
	seslog = loggerManager.seslog
	log = loggerManager.deflog
}

// TODO: use async writer only on Error and above?

// NewLoggerManager creates a new logger manager with default settings
func NewLoggerManager() *LoggerManager {
	writer := &plog.IOWriter{Writer: os.Stderr}

	lm := &LoggerManager{
		writer:  writer,
		loggers: make(map[LoggerName]*plog.Logger),
	}

	// Create the loggers and store them in the map
	lm.loggers[ConsumerLogger] = &plog.Logger{
		Level:   plog.WarnLevel, // Higher threshold for hot path
		Writer:  writer,
		Context: plog.NewContext(nil).Str("component", string(ConsumerLogger)).Value(),
	}
	lm.loggers[SessionLogger] = &plog.Logger{
		Level:   plog.InfoLevel,
		Writer:  writer,
		Context: plog.NewContext(nil).Str("component", string(SessionLogger)).Value(),
	}
	lm.loggers[DefaultLogger] = &plog.Logger{
		Level:   plog.InfoLevel,
		Writer:  writer,
		Context: plog.NewContext(nil).Str("component", string(DefaultLogger)).Value(),
	}

	// Default backoff configuration.
	backoffConfig := logsampler.BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     1 * time.Hour,
		Factor:          1.2,
		ResetInterval:   10 * time.Minute,
	}

	// The sampler needs a logger to report summaries for inactive keys.
	reporter := &plogSummaryReporter{logger: lm.loggers[DefaultLogger]}
	lm.sampler = logsampler.NewDeduplicatingSampler(backoffConfig, reporter)

	// Assign to convenient direct-access variables
	lm.conlog = lm.loggers[ConsumerLogger]
	lm.seslog = lm.loggers[SessionLogger]
	lm.deflog = lm.loggers[DefaultLogger]

	return lm
}

// SetBaseContext changes the base context for all loggers.
// This allows a consumer to add its own contextual fields.
func (lm *LoggerManager) SetBaseContext(ctx []byte) {
	for name, logger := range lm.loggers {
		logger.Context = plog.NewContext(ctx).Str("component", string(name)).Value()
	}
}

// SetSampler changes the active sampler. It safely closes the previous sampler.
func (lm *LoggerManager) SetSampler(sampler Sampler) {
	if lm.sampler != nil {
		lm.sampler.Close()
	}
	lm.sampler = sampler
	if conlog != nil {
		conlog.sampler = sampler
	}
}

// SetWriter changes the writer for all loggers
func (lm *LoggerManager) SetWriter(writer plog.Writer) {
	lm.writer = writer
	for _, logger := range lm.loggers {
		logger.Writer = writer
	}
}

// SetLogLevels sets the log level for one or more loggers.
// Use the exported LoggerName constants (e.g., etw.ConsumerLogger) as keys.
func (lm *LoggerManager) SetLogLevels(levels map[LoggerName]plog.Level) {
	for name, level := range levels {
		if logger, ok := lm.loggers[name]; ok {
			logger.SetLevel(level)
		}
	}
}

// GetSampler returns the error sampler for hot path error logging
func (lm *LoggerManager) GetSampler() Sampler {
	return lm.sampler
}

// SetSampler sets the global sampler for hot-path logging.
func SetSampler(s Sampler) {
	loggerManager.SetSampler(s)
}

// SetLogLevels sets the log level for one or more loggers globally.
func SetLogLevels(levels map[LoggerName]plog.Level) {
	loggerManager.SetLogLevels(levels)
}

// SetLogLevelsAll sets all registered loggers to the given level
func SetLogLevelsAll(level plog.Level) {
	levels := make(map[LoggerName]plog.Level)
	for name := range loggerManager.loggers {
		levels[name] = level
	}
	SetLogLevels(levels)
}

func SetLogDebugLevel() { SetLogLevelsAll(plog.DebugLevel) }
func SetLogInfoLevel()  { SetLogLevelsAll(plog.InfoLevel) }
func SetLogWarnLevel()  { SetLogLevelsAll(plog.WarnLevel) }
func SetLogErrorLevel() { SetLogLevelsAll(plog.ErrorLevel) }
func SetLogFatalLevel() { SetLogLevelsAll(plog.FatalLevel) }
func SetLogPanicLevel() { SetLogLevelsAll(plog.PanicLevel) }
func SetLogTraceLevel() { SetLogLevelsAll(plog.TraceLevel) }

// DisableLogging sets all loggers to OffLevel (no output)
func DisableLogging() {
	SetLogLevelsAll(99) // NoLevel
}

// SetWriter sets writer for all loggers
func SetLogWriter(writer plog.Writer) { loggerManager.SetWriter(writer) }

// SetBaseContext sets the base context for all loggers
func SetLogBaseContext(ctx []byte) { loggerManager.SetBaseContext(ctx) }

// GetLogManager returns the global logger manager
func GetLogManager() *LoggerManager { return loggerManager }
