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
	"go.opentelemetry.io/otel/trace" // ✅ THIS LINE FIXES ALL `undefined: trace` ERRORS
)

var tracer = otel.Tracer("eos.telemetry")

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

// TraceID extracts the trace ID from a span.
func TraceID(span trace.Span) string {
	if span == nil {
		return ""
	}
	spanCtx := span.SpanContext()
	if !spanCtx.IsValid() {
		return ""
	}
	return spanCtx.TraceID().String()
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

func StartSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	if !IsEnabled() {
		return ctx, trace.SpanFromContext(context.Background())
	}
	return tracer.Start(ctx, name)
}

// fallback hostname provider
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
