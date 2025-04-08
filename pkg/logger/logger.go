/* pkg/logger/logger.go */

package logger

var (
	WithCommandLogging     = withCommandLogging
	PlatformLogPaths       = platformLogPaths
	ReadLogFile            = readLogFile
	LogCommandStart        = logCommandStart
	LogCommandEnd          = logCommandEnd
	ResolveLogPath         = resolveLogPath
	EnsureLogPermissions   = ensureLogPermissions
	IsIgnorableSyncError   = isIgnorableSyncError
	IsStrict               = isStrict
	ParseLogLevel          = parseLogLevel
	NewFallbackLogger      = newFallbackLogger
	DefaultConfig          = defaultConfig
	GetLogger              = getLogger
	InitializeWithFallback = initializeWithFallback
	InitializeWithConfig   = initializeWithConfig
	Sync                   = sync
	GetLogFileWriter       = getLogFileWriter
)
