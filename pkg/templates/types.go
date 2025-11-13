// pkg/templates/types.go
// Type definitions for template rendering system

package templates

import (
	"text/template"
	"time"
)

// TemplateData holds data for template rendering
type TemplateData struct {
	// Data is the map of variables to substitute in the template
	Data map[string]interface{}

	// Funcs are custom template functions (optional)
	Funcs template.FuncMap
}

// RenderOptions controls template rendering behavior
type RenderOptions struct {
	// MaxSize is the maximum template size in bytes (default: 1MB)
	MaxSize int64

	// Timeout is the maximum time allowed for rendering (default: 30s)
	Timeout time.Duration

	// DisableRateLimiting bypasses rate limiting (use for system operations)
	DisableRateLimiting bool
}

// DefaultRenderOptions returns sensible defaults
func DefaultRenderOptions() *RenderOptions {
	return &RenderOptions{
		MaxSize:             1 * 1024 * 1024, // 1MB
		Timeout:             30 * time.Second,
		DisableRateLimiting: false,
	}
}
