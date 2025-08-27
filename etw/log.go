//go:build windows

// Package etw provides simple logging using phuslu/log library
// and a high-performance sampler for hot paths.

package etw

import (
	"os"
	"time"

	"github.com/tekert/goetw/logsampler"
	"github.com/tekert/goetw/logsampler/adapters/phusluadapter"

	plog "github.com/phuslu/log"
)

// LoggerName defines the name of a logger for configuration.
type LoggerName string

// LoggerName defines the name of a logger for configuration.
// Available logger names. Use these as keys when configuring log levels.
const (
	ConsumerLogger LoggerName = "consumer"
	SessionLogger  LoggerName = "session"
	DefaultLogger  LoggerName = "default"
)

// SampledLogger is an alias for the reusable pshuslug SampledLogger.
type SampledLogger = phusluadapter.SampledLogger

// LoggerManager manages all three loggers
type LoggerManager struct {
	writer  plog.Writer
	sampler logsampler.Sampler
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
	conlog = phusluadapter.NewSampledLogger(
		loggerManager.loggers[ConsumerLogger],
		loggerManager.sampler,
	)
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
	reporter := &phusluadapter.SummaryReporter{Logger: lm.loggers[DefaultLogger]}
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
func (lm *LoggerManager) SetSampler(sampler logsampler.Sampler) {
	if lm.sampler != nil {
		lm.sampler.Close()
	}
	lm.sampler = sampler
	if conlog != nil {
		conlog.Sampler = sampler
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
func (lm *LoggerManager) GetSampler() logsampler.Sampler {
	return lm.sampler
}

// SetSampler sets the global sampler for hot-path logging.
func SetSampler(s logsampler.Sampler) {
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
