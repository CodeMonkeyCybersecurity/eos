// pkg/telemetry/telemetry.go
package telemetry

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	cerr "github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	noop "go.opentelemetry.io/otel/trace/noop"
)

var (
	tracer trace.Tracer = noop.NewTracerProvider().Tracer("") // ✅ default fallback
)

// Init configures OpenTelemetry; call this once in main().
func Init(serviceName string) error {
	if !enabled() {
		tracer = noop.NewTracerProvider().Tracer(serviceName)
		return nil
	}

	exp, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		return cerr.Wrap(err, "failed to create stdout exporter")
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(sdkresource.NewWithAttributes(
			semconv.SchemaURL,
			attribute.String("service.name", serviceName),
			attribute.String("host.name", hostname()),
		)),
	)

	otel.SetTracerProvider(tp)
	tracer = tp.Tracer(serviceName)
	return nil
}

// Start a telemetry span with optional attributes.
func Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// TrackCommand records a span around a CLI command.
func TrackCommand(ctx context.Context, name string, success bool, dur time.Duration, args ...string) {
	_, span := Start(ctx, name,
		attribute.Bool("success", success),
		attribute.Int64("duration_ms", dur.Milliseconds()),
		attribute.String("user_id", anonymousID()),
		attribute.String("args", truncate(strings.Join(args, " "))),
	)
	defer span.End()
}

// enabled returns true if ~/.eos/telemetry_on exists.
func enabled() bool {
	path := filepath.Join(os.Getenv("HOME"), ".eos", "telemetry_on")
	_, err := os.Stat(path)
	return err == nil
}

// anonymousID returns a persisted or newly generated anonymous ID.
func anonymousID() string {
	path := filepath.Join(os.Getenv("HOME"), ".eos", "telemetry_id")
	if b, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(b))
	}
	id := "anon-" + uuid.New().String()
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	_ = os.WriteFile(path, []byte(id), 0600)
	return id
}

func truncate(s string) string {
	if len(s) > 256 {
		return s[:256] + "…"
	}
	return s
}

func hostname() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "unknown"
}