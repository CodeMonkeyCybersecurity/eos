// pkg/telemetry/opentelemetry.go

package telemetry

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoserr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

// global tracer
var tracer = otel.Tracer("eos.telemetry")

// Init sets up a basic stdout exporter for local debugging
func Init(ctx context.Context) error {
	exp, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		return fmt.Errorf("failed to create exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("eos"),
			attribute.String("host", hostnameOrFallback()),
		)),
	)

	otel.SetTracerProvider(tp)
	return nil
}

// TrackCommand records a command invocation
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

// fallback for hostname field
func hostnameOrFallback() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
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
	if eoserr.IsExpectedUserError(err) {
		return "user"
	}
	return "system"
}
