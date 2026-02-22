// pkg/telemetry/telemetry.go
package telemetry

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

var tracer trace.Tracer

var sensitiveAssignmentPattern = regexp.MustCompile(`(?i)(token|password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|cookie)=([^&\s]+)`)

// Init configures OpenTelemetry; call this early in main().
func Init(service string) error {
	if !enabled() {
		tp := noop.NewTracerProvider()
		otel.SetTracerProvider(tp)
		tracer = tp.Tracer(service)
		return nil
	}

	// Create telemetry log directory with fallback chain
	var telemetryDir string
	var dirErr error

	// Try system directory first
	telemetryDir = "/var/log/eos"
	if err := os.MkdirAll(telemetryDir, shared.ServiceDirPerm); err != nil {
		// Fallback to user home
		telemetryDir = filepath.Join(os.Getenv("HOME"), ".eos", "telemetry")
		if err := os.MkdirAll(telemetryDir, shared.ServiceDirPerm); err != nil {
			// Final fallback to temp directory for tests
			telemetryDir = filepath.Join(os.TempDir(), "eos-telemetry")
			if dirErr = os.MkdirAll(telemetryDir, shared.ServiceDirPerm); dirErr != nil {
				// If all fallbacks fail, use no-op tracer
				tp := noop.NewTracerProvider()
				otel.SetTracerProvider(tp)
				tracer = tp.Tracer(service)
				return nil
			}
		}
	}

	// Open telemetry file for appending (JSONL format)
	telemetryFile := filepath.Join(telemetryDir, "telemetry.jsonl")
	file, err := os.OpenFile(telemetryFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// If file opening fails, use no-op tracer
		tp := noop.NewTracerProvider()
		otel.SetTracerProvider(tp)
		tracer = tp.Tracer(service)
		return nil
	}

	// Use stdout exporter but write to file instead of stdout
	exp, err := stdouttrace.New(
		stdouttrace.WithWriter(file),
		stdouttrace.WithoutTimestamps(), // Spans already have timestamps
	)
	if err != nil {
		_ = file.Close() // Best effort cleanup
		return cerr.Wrap(err, "failed to create file exporter")
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(
			sdkresource.NewWithAttributes(
				semconv.SchemaURL,
				attribute.String("service.name", service),
				attribute.String("host.name", hostname()),
			),
		),
	)

	otel.SetTracerProvider(tp)
	tracer = tp.Tracer(service)
	return nil
}

// Start a telemetry span with optional attributes.
func Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if ctx == nil {
		ctx = context.Background() //  Safe fallback
	}

	// Safety check: if tracer is nil, initialize a no-op tracer
	if tracer == nil {
		tp := noop.NewTracerProvider()
		tracer = tp.Tracer("eos-fallback")
	}

	return tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

func TrackCommand(ctx context.Context, name string, success bool, durationMs int64, tags map[string]string) {
	if !IsEnabled() {
		return
	}

	// Safety check: if tracer is nil, initialize a no-op tracer
	if tracer == nil {
		tp := noop.NewTracerProvider()
		tracer = tp.Tracer("eos-fallback")
	}

	_, span := tracer.Start(ctx, name)
	defer span.End()

	attrs := []attribute.KeyValue{
		attribute.Bool("success", success),
		attribute.Int64("duration_ms", durationMs),
		attribute.String("user_id", AnonTelemetryID()),
	}

	for k, v := range tags {
		v = sanitizeTagValue(k, v)
		if k == "args" && len(v) > 256 {
			v = v[:256] + "..."
		}
		attrs = append(attrs, attribute.String(k, v))
	}

	span.SetAttributes(attrs...)
}

func enabled() bool {
	path := filepath.Join(os.Getenv("HOME"), ".eos", "telemetry_on")
	_, err := os.Stat(path)
	return err == nil
}

func hostname() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "unknown"
}

func TruncateOrHashArgs(args []string) string {
	full := sanitizeRawSecrets(strings.Join(args, " "))
	if len(full) > 256 {
		return full[:256] + "..."
	}
	return full
}

func sanitizeTagValue(key, value string) string {
	if value == "" {
		return value
	}

	if isSensitiveKey(key) {
		return "[REDACTED]"
	}

	if sanitizedURL, ok := sanitizeURLString(value); ok {
		value = sanitizedURL
	}

	return sanitizeRawSecrets(value)
}

func isSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if k == "" {
		return false
	}

	sensitiveParts := []string{
		"token",
		"secret",
		"password",
		"passwd",
		"apikey",
		"api_key",
		"authorization",
		"cookie",
		"private_key",
		"client_secret",
	}

	for _, part := range sensitiveParts {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}

func sanitizeURLString(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}

	if u.User != nil {
		u.User = url.User("REDACTED")
	}

	q := u.Query()
	for k := range q {
		if isSensitiveKey(k) {
			q.Set(k, "[REDACTED]")
		}
	}
	u.RawQuery = q.Encode()

	return u.String(), true
}

func sanitizeRawSecrets(raw string) string {
	return sensitiveAssignmentPattern.ReplaceAllString(raw, "$1=[REDACTED]")
}

func CommandCategory(cmd string) string {
	switch {
	case strings.HasPrefix(cmd, "vault"):
		return "vault"
	case strings.HasPrefix(cmd, "kvm"):
		return "kvm"
	case strings.HasPrefix(cmd, "enable"), strings.HasPrefix(cmd, "create"):
		return "lifecycle"
	default:
		return "general"
	}
}

func ClassifyError(err error) string {
	if err == nil {
		return ""
	}
	return "system"
}

func IsEnabled() bool {
	// TODO: replace with Vault-backed config once available
	path := filepath.Join(os.Getenv("HOME"), ".eos", "telemetry_on")
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}

func AnonTelemetryID() string {
	path := filepath.Join(os.Getenv("HOME"), ".eos", "telemetry_id")

	if data, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(data))
	}

	id := "anon-" + uuid.New().String()
	_ = os.MkdirAll(filepath.Dir(path), shared.SecretDirPerm)
	_ = os.WriteFile(path, []byte(id), shared.SecretFilePerm)

	return id
}
