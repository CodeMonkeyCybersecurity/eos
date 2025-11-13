# pkg/templates

*Last Updated: 2025-10-21*

Unified, security-hardened template rendering system for Eos.

## Purpose

This package provides centralized template rendering with built-in security features:
- **Rate limiting**: Prevents DoS via rapid template operations (10/min)
- **Size limits**: Prevents resource exhaustion (1MB max)
- **Timeout enforcement**: Prevents infinite loops (30s max)
- **Context cancellation**: Supports graceful shutdown
- **Structured logging**: Observability via OpenTelemetry

## Usage

### Basic String Template

```go
import (
    "context"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/templates"
)

tmpl := `Hello {{.Name}}, welcome to {{.Service}}!`
data := map[string]interface{}{
    "Name":    "Henry",
    "Service": "Eos",
}

result, err := templates.RenderString(ctx, tmpl, data)
// Output: "Hello Henry, welcome to Eos!"
```

### Rendering from File

```go
result, err := templates.RenderFile(ctx, "/path/to/template.tmpl", data)
```

### Custom Options

```go
renderer := templates.NewRenderer(logger)
opts := &templates.RenderOptions{
    MaxSize:             2 * 1024 * 1024, // 2MB
    Timeout:             60 * time.Second,
    DisableRateLimiting: true, // For system operations
}

result, err := renderer.RenderString(ctx, tmpl, data, opts)
```

### Embedded Templates

```go
//go:embed hecate/*.tmpl
var hecateTemplates embed.FS

result, err := renderer.RenderEmbedded(ctx, hecateTemplates, "hecate/docker.tmpl", data, nil)
```

## Template Locations

- **Hecate**: `pkg/templates/hecate/*.tmpl` - Reverse proxy infrastructure templates
- **Add more as packages migrate...**

## Migration Guide

### Old Pattern (Per-Package)

```go
// OLD: pkg/hecate/utils.go
func renderTemplateFromString(tmplStr string, data interface{}) (string, error) {
    tmpl, err := template.New("compose").Parse(tmplStr)
    if err != nil {
        return "", err
    }
    var buf bytes.Buffer
    if err := tmpl.Execute(&buf, data); err != nil {
        return "", err
    }
    return buf.String(), nil
}
```

### New Pattern (Unified)

```go
// NEW: Use pkg/templates
import "github.com/CodeMonkeyCybersecurity/eos/pkg/templates"

result, err := templates.RenderString(ctx, tmplStr, data)
```

**Benefits:**
- ✓ Automatic rate limiting
- ✓ Size validation
- ✓ Timeout protection
- ✓ Structured logging
- ✓ Context cancellation

## Security Features

### Rate Limiting
- **Default**: 10 renders per minute
- **Burst**: 5 renders
- **Override**: Set `DisableRateLimiting: true` in options

### Size Limits
- **Default**: 1MB max template size
- **Override**: Set `MaxSize` in options
- **Rationale**: Prevents memory exhaustion attacks

### Timeout Enforcement
- **Default**: 30 seconds max render time
- **Override**: Set `Timeout` in options
- **Rationale**: Prevents infinite loops in templates

### Context Cancellation
All rendering operations respect `context.Context` cancellation for graceful shutdown.

## Testing

```go
func TestRenderTemplate(t *testing.T) {
    ctx := context.Background()
    tmpl := `Count: {{.Count}}`
    data := map[string]interface{}{"Count": 42}

    result, err := templates.RenderString(ctx, tmpl, data)
    assert.NoError(t, err)
    assert.Equal(t, "Count: 42", result)
}
```

## Performance

- **Rendering**: ~0.1-1ms for typical templates (<10KB)
- **Rate limiting overhead**: ~0.01ms
- **Memory**: Scales with template size (max 1MB default)

## Deprecation Policy

Old `renderTemplateFromString()` functions in individual packages will be:
1. Marked as deprecated (with `// Deprecated:` comment)
2. Wrapped to call `pkg/templates` internally
3. Removed after 2 minor releases

## References

- Go text/template docs: https://pkg.go.dev/text/template
- Security implementation: Based on `pkg/fileops/template_operations.go`
- Rate limiting: `golang.org/x/time/rate`
