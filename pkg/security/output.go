// pkg/security/output.go

package security

import (
	"context"
	"fmt"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecureOutput provides sanitized output for user-facing content
type SecureOutput struct {
	ctx context.Context
}

// NewSecureOutput creates a new secure output helper
func NewSecureOutput(ctx context.Context) *SecureOutput {
	return &SecureOutput{
		ctx: ctx,
	}
}

// Info logs user-facing information with sanitized content
func (so *SecureOutput) Info(message string, fields ...zap.Field) {
	sanitizedMessage := EscapeOutput(message)
	sanitizedFields := so.sanitizeFields(fields)

	otelzap.Ctx(so.ctx).Info(sanitizedMessage, sanitizedFields...)
}

// Success logs successful operations with sanitized content
func (so *SecureOutput) Success(message string, fields ...zap.Field) {
	sanitizedMessage := EscapeOutput(message)
	sanitizedFields := so.sanitizeFields(fields)

	// Add success indicator
	allFields := append(sanitizedFields, zap.String("status", "success"))
	otelzap.Ctx(so.ctx).Info(sanitizedMessage, allFields...)
}

// Warning logs warnings with sanitized content
func (so *SecureOutput) Warning(message string, fields ...zap.Field) {
	sanitizedMessage := EscapeOutput(message)
	sanitizedFields := so.sanitizeFields(fields)

	otelzap.Ctx(so.ctx).Warn(sanitizedMessage, sanitizedFields...)
}

// Error logs errors with sanitized content
func (so *SecureOutput) Error(message string, err error, fields ...zap.Field) {
	sanitizedMessage := EscapeOutput(message)
	sanitizedFields := so.sanitizeFields(fields)

	// Sanitize error message
	sanitizedError := fmt.Errorf("%s", EscapeOutput(err.Error()))
	allFields := append(sanitizedFields, zap.Error(sanitizedError))

	otelzap.Ctx(so.ctx).Error(sanitizedMessage, allFields...)
}

// Result logs command results with sanitized content
func (so *SecureOutput) Result(operation string, data interface{}, fields ...zap.Field) {
	sanitizedMessage := EscapeOutput(fmt.Sprintf("%s completed", operation))
	sanitizedFields := so.sanitizeFields(fields)

	// Sanitize the data field
	sanitizedData := so.sanitizeData(data)
	allFields := append(sanitizedFields,
		zap.String("operation", EscapeOutput(operation)),
		zap.Any("result", sanitizedData))

	otelzap.Ctx(so.ctx).Info(sanitizedMessage, allFields...)
}

// Progress logs progress updates with sanitized content
func (so *SecureOutput) Progress(step string, current, total int, fields ...zap.Field) {
	sanitizedStep := EscapeOutput(step)
	sanitizedFields := so.sanitizeFields(fields)

	allFields := append(sanitizedFields,
		zap.String("step", sanitizedStep),
		zap.Int("current", current),
		zap.Int("total", total),
		zap.Float64("progress_percent", float64(current)/float64(total)*100))

	otelzap.Ctx(so.ctx).Info("Progress update", allFields...)
}

// List logs lists of items with sanitized content
func (so *SecureOutput) List(title string, items []string, fields ...zap.Field) {
	sanitizedTitle := EscapeOutput(title)
	sanitizedFields := so.sanitizeFields(fields)

	// Sanitize all items
	sanitizedItems := make([]string, len(items))
	for i, item := range items {
		sanitizedItems[i] = EscapeOutput(item)
	}

	allFields := append(sanitizedFields,
		zap.Strings("items", sanitizedItems),
		zap.Int("count", len(sanitizedItems)))

	otelzap.Ctx(so.ctx).Info(sanitizedTitle, allFields...)
}

// Table logs tabular data with sanitized content
func (so *SecureOutput) Table(title string, headers []string, rows [][]string, fields ...zap.Field) {
	sanitizedTitle := EscapeOutput(title)
	sanitizedFields := so.sanitizeFields(fields)

	// Sanitize headers
	sanitizedHeaders := make([]string, len(headers))
	for i, header := range headers {
		sanitizedHeaders[i] = EscapeOutput(header)
	}

	// Sanitize all rows
	sanitizedRows := make([][]string, len(rows))
	for i, row := range rows {
		sanitizedRows[i] = make([]string, len(row))
		for j, cell := range row {
			sanitizedRows[i][j] = EscapeOutput(cell)
		}
	}

	allFields := append(sanitizedFields,
		zap.Strings("headers", sanitizedHeaders),
		zap.Any("rows", sanitizedRows),
		zap.Int("row_count", len(sanitizedRows)))

	otelzap.Ctx(so.ctx).Info(sanitizedTitle, allFields...)
}

// sanitizeFields sanitizes zap fields
func (so *SecureOutput) sanitizeFields(fields []zap.Field) []zap.Field {
	sanitized := make([]zap.Field, len(fields))
	for i, field := range fields {
		sanitized[i] = so.sanitizeField(field)
	}
	return sanitized
}

// sanitizeField sanitizes a single zap field
func (so *SecureOutput) sanitizeField(field zap.Field) zap.Field {
	// Handle string fields by checking the String field
	if field.String != "" {
		return zap.String(field.Key, EscapeOutput(field.String))
	}

	// Handle interface fields (errors, any types)
	if field.Interface != nil {
		switch v := field.Interface.(type) {
		case error:
			sanitizedErr := fmt.Errorf("%s", EscapeOutput(v.Error()))
			return zap.Error(sanitizedErr)
		case string:
			return zap.String(field.Key, EscapeOutput(v))
		default:
			// For other interface types, recursively sanitize if possible
			return zap.Any(field.Key, so.sanitizeData(v))
		}
	}

	// For numeric, boolean, and other simple types, return as-is
	return field
}

// sanitizeData sanitizes arbitrary data
func (so *SecureOutput) sanitizeData(data interface{}) interface{} {
	switch v := data.(type) {
	case string:
		return EscapeOutput(v)
	case []string:
		sanitized := make([]string, len(v))
		for i, item := range v {
			sanitized[i] = EscapeOutput(item)
		}
		return sanitized
	case map[string]string:
		sanitized := make(map[string]string)
		for key, value := range v {
			sanitized[EscapeOutput(key)] = EscapeOutput(value)
		}
		return sanitized
	case map[string]interface{}:
		sanitized := make(map[string]interface{})
		for key, value := range v {
			sanitized[EscapeOutput(key)] = so.sanitizeData(value)
		}
		return sanitized
	default:
		// For other types, return as-is (numbers, bools, etc. are safe)
		return data
	}
}

// Package-level convenience functions

// LogInfo provides a package-level function for secure info logging
func LogInfo(ctx context.Context, message string, fields ...zap.Field) {
	output := NewSecureOutput(ctx)
	output.Info(message, fields...)
}

// LogSuccess provides a package-level function for secure success logging
func LogSuccess(ctx context.Context, message string, fields ...zap.Field) {
	output := NewSecureOutput(ctx)
	output.Success(message, fields...)
}

// LogWarning provides a package-level function for secure warning logging
func LogWarning(ctx context.Context, message string, fields ...zap.Field) {
	output := NewSecureOutput(ctx)
	output.Warning(message, fields...)
}

// LogError provides a package-level function for secure error logging
func LogError(ctx context.Context, message string, err error, fields ...zap.Field) {
	output := NewSecureOutput(ctx)
	output.Error(message, err, fields...)
}

// LogResult provides a package-level function for secure result logging
func LogResult(ctx context.Context, operation string, data interface{}, fields ...zap.Field) {
	output := NewSecureOutput(ctx)
	output.Result(operation, data, fields...)
}

// LogProgress provides a package-level function for secure progress logging
func LogProgress(ctx context.Context, step string, current, total int, fields ...zap.Field) {
	output := NewSecureOutput(ctx)
	output.Progress(step, current, total, fields...)
}

// LogList provides a package-level function for secure list logging
func LogList(ctx context.Context, title string, items []string, fields ...zap.Field) {
	output := NewSecureOutput(ctx)
	output.List(title, items, fields...)
}

// LogTable provides a package-level function for secure table logging
func LogTable(ctx context.Context, title string, headers []string, rows [][]string, fields ...zap.Field) {
	output := NewSecureOutput(ctx)
	output.Table(title, headers, rows, fields...)
}
