package logger

import (
	"fmt"
	"sort"
	"strings"

	"go.uber.org/zap/zapcore"
)

// terminalConsoleCore wraps a zapcore.Core and renders "terminal prompt" logs
// as plain text for human-friendly CLI output.
type terminalConsoleCore struct {
	base zapcore.Core
}

func newTerminalConsoleCore(base zapcore.Core) zapcore.Core {
	return &terminalConsoleCore{base: base}
}

func (c *terminalConsoleCore) Enabled(level zapcore.Level) bool {
	return c.base.Enabled(level)
}

func (c *terminalConsoleCore) With(fields []zapcore.Field) zapcore.Core {
	return &terminalConsoleCore{base: c.base.With(fields)}
}

func (c *terminalConsoleCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if strings.HasPrefix(entry.Message, "terminal prompt:") {
		return ce.AddCore(entry, c)
	}
	return c.base.Check(entry, ce)
}

func (c *terminalConsoleCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	if strings.HasPrefix(entry.Message, "terminal prompt:") {
		c.writeTerminal(entry.Message, fields)
		return nil
	}
	return c.base.Write(entry, fields)
}

func (c *terminalConsoleCore) Sync() error {
	return c.base.Sync()
}

func (c *terminalConsoleCore) writeTerminal(message string, fields []zapcore.Field) {
	text := strings.TrimSpace(strings.TrimPrefix(message, "terminal prompt:"))
	if text != "" {
		c.printLines(text)
	}

	if len(fields) > 0 {
		enc := zapcore.NewMapObjectEncoder()
		for _, field := range fields {
			field.AddTo(enc)
		}

		if output, ok := enc.Fields["output"]; ok {
			c.printLines(fmt.Sprint(output))
			delete(enc.Fields, "output")
		}

		if len(enc.Fields) > 0 {
			keys := make([]string, 0, len(enc.Fields))
			for key := range enc.Fields {
				keys = append(keys, key)
			}
			sort.Strings(keys)

			for _, key := range keys {
				c.printLines(fmt.Sprintf("%s: %v", key, enc.Fields[key]))
			}
		}
	}

	if text == "" && len(fields) == 0 {
		fmt.Println()
	}
}

func (c *terminalConsoleCore) printLines(value string) {
	if value == "" {
		fmt.Println()
		return
	}

	for _, line := range strings.Split(value, "\n") {
		fmt.Println(line)
	}
}
