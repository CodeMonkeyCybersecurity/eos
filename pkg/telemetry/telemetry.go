// pkg/telemetry/telemetry.go
package telemetry

import (
	"context"
	"os"
	"path/filepath"
	"strings"

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

// Init configures OpenTelemetry; call this early in main().
func Init(service string) error {
	if !enabled() {
		tp := noop.NewTracerProvider()
		otel.SetTracerProvider(tp)
		tracer = tp.Tracer(service)
		return nil
	}

	// Create telemetry log directory
	telemetryDir := "/var/log/eos"
	if err := os.MkdirAll(telemetryDir, 0755); err != nil {
		// Fallback to user home if system directory fails
		telemetryDir = filepath.Join(os.Getenv("HOME"), ".eos", "telemetry")
		if err := os.MkdirAll(telemetryDir, 0755); err != nil {
			return cerr.Wrap(err, "failed to create telemetry directory")
		}
	}

	// Open telemetry file for appending (JSONL format)
	telemetryFile := filepath.Join(telemetryDir, "telemetry.jsonl")
	file, err := os.OpenFile(telemetryFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return cerr.Wrap(err, "failed to open telemetry file")
	}

	// Use stdout exporter but write to file instead of stdout
	exp, err := stdouttrace.New(
		stdouttrace.WithWriter(file),
		stdouttrace.WithoutTimestamps(), // Spans already have timestamps
	)
	if err != nil {
		file.Close()
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
		ctx = context.Background() // 🔧 Safe fallback
	}
	return tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

func TrackCommand(ctx context.Context, name string, success bool, durationMs int64, tags map[string]string) {
	if !IsEnabled() {
		return
	}

	_, span := tracer.Start(ctx, name)
	defer span.End()

	attrs := []attribute.KeyValue{
		attribute.Bool("success", success),
		attribute.Int64("duration_ms", durationMs),
		attribute.String("user_id", AnonTelemetryID()),
	}

	for k, v := range tags {
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
	full := strings.Join(args, " ")
	if len(full) > 256 {
		return full[:256] + "..."
	}
	return full
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
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	_ = os.WriteFile(path, []byte(id), 0600)

	return id
}
