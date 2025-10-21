// pkg/templates/render.go
// Security-hardened template rendering system
//
// This package provides centralized, secure template rendering with:
// - Rate limiting (prevents DoS via rapid template operations)
// - Size limits (prevents resource exhaustion)
// - Timeout enforcement (prevents infinite loops)
// - Context cancellation support
// - Structured logging

package templates

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"os"
	"sync"
	"text/template"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

const (
	// SECURITY: Maximum template size to prevent resource exhaustion
	DefaultMaxTemplateSize = 1 * 1024 * 1024 // 1MB

	// SECURITY: Timeout for template execution to prevent infinite loops
	DefaultTemplateTimeout = 30 * time.Second

	// SECURITY: Rate limit burst for template operations
	RateLimitBurst = 5

	// SECURITY: Rate limit for template operations (10 per minute)
	RateLimitPerMinute = 10
)

var (
	// Global rate limiter for template operations
	globalRateLimiter = rate.NewLimiter(rate.Every(time.Minute/RateLimitPerMinute), RateLimitBurst)
	rateLimiterMu     sync.Mutex
)

// Renderer provides secure template rendering
type Renderer struct {
	logger *zap.Logger
}

// NewRenderer creates a new template renderer
func NewRenderer(logger *zap.Logger) *Renderer {
	if logger == nil {
		logger = zap.L() // Use standard zap logger if none provided
	}
	return &Renderer{
		logger: logger.Named("template-renderer"),
	}
}

// RenderString renders a template from a string with the given data
func (r *Renderer) RenderString(ctx context.Context, tmplStr string, data interface{}, opts *RenderOptions) (string, error) {
	if opts == nil {
		opts = DefaultRenderOptions()
	}

	// SECURITY: Apply rate limiting
	if !opts.DisableRateLimiting {
		rateLimiterMu.Lock()
		if !globalRateLimiter.Allow() {
			rateLimiterMu.Unlock()
			r.logger.Warn("Template rendering rate limit exceeded")
			return "", fmt.Errorf("rate limit exceeded for template operations (max %d/min)", RateLimitPerMinute)
		}
		rateLimiterMu.Unlock()
	}

	// SECURITY: Check template size
	if int64(len(tmplStr)) > opts.MaxSize {
		r.logger.Error("Template size exceeds limit",
			zap.Int("size", len(tmplStr)),
			zap.Int64("max_size", opts.MaxSize))
		return "", fmt.Errorf("template size %d exceeds limit %d", len(tmplStr), opts.MaxSize)
	}

	// SECURITY: Create timeout context
	renderCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	// Parse template
	tmpl, err := template.New("template").Parse(tmplStr)
	if err != nil {
		r.logger.Error("Failed to parse template", zap.Error(err))
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	// Render with timeout
	resultChan := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			errChan <- fmt.Errorf("failed to execute template: %w", err)
			return
		}
		resultChan <- buf.String()
	}()

	// Wait for result or timeout
	select {
	case <-renderCtx.Done():
		r.logger.Error("Template rendering timed out",
			zap.Duration("timeout", opts.Timeout))
		return "", fmt.Errorf("template rendering timed out after %s", opts.Timeout)
	case err := <-errChan:
		return "", err
	case result := <-resultChan:
		r.logger.Debug("Template rendered successfully",
			zap.Int("output_size", len(result)))
		return result, nil
	}
}

// RenderFile renders a template from a file with the given data
func (r *Renderer) RenderFile(ctx context.Context, templatePath string, data interface{}, opts *RenderOptions) (string, error) {
	if opts == nil {
		opts = DefaultRenderOptions()
	}

	r.logger.Debug("Rendering template from file",
		zap.String("path", templatePath))

	// SECURITY: Check file size before reading
	fileInfo, err := os.Stat(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to stat template file %s: %w", templatePath, err)
	}

	if fileInfo.Size() > opts.MaxSize {
		r.logger.Error("Template file size exceeds limit",
			zap.String("path", templatePath),
			zap.Int64("size", fileInfo.Size()),
			zap.Int64("max_size", opts.MaxSize))
		return "", fmt.Errorf("template file %s size %d exceeds limit %d",
			templatePath, fileInfo.Size(), opts.MaxSize)
	}

	// Read template file
	tmplBytes, err := os.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to read template file %s: %w", templatePath, err)
	}

	// Render using string renderer
	return r.RenderString(ctx, string(tmplBytes), data, opts)
}

// RenderEmbedded renders a template from an embedded filesystem
func (r *Renderer) RenderEmbedded(ctx context.Context, fs embed.FS, templatePath string, data interface{}, opts *RenderOptions) (string, error) {
	if opts == nil {
		opts = DefaultRenderOptions()
	}

	r.logger.Debug("Rendering embedded template",
		zap.String("path", templatePath))

	// Read from embedded FS
	tmplBytes, err := fs.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to read embedded template %s: %w", templatePath, err)
	}

	// Render using string renderer
	return r.RenderString(ctx, string(tmplBytes), data, opts)
}

// RenderToFile renders a template and writes the output to a file
func (r *Renderer) RenderToFile(ctx context.Context, templatePath, outputPath string, data interface{}, opts *RenderOptions) error {
	r.logger.Info("Rendering template to file",
		zap.String("template", templatePath),
		zap.String("output", outputPath))

	// Render template
	result, err := r.RenderFile(ctx, templatePath, data, opts)
	if err != nil {
		return err
	}

	// Write to output file
	if err := os.WriteFile(outputPath, []byte(result), 0644); err != nil {
		return fmt.Errorf("failed to write output file %s: %w", outputPath, err)
	}

	r.logger.Info("Template rendered to file successfully",
		zap.String("output", outputPath),
		zap.Int("size", len(result)))

	return nil
}

// Global convenience functions for backward compatibility

// RenderString is a convenience wrapper for quick template rendering
func RenderString(ctx context.Context, tmplStr string, data interface{}) (string, error) {
	renderer := NewRenderer(nil)
	return renderer.RenderString(ctx, tmplStr, data, DefaultRenderOptions())
}

// RenderFile is a convenience wrapper for rendering from a file
func RenderFile(ctx context.Context, templatePath string, data interface{}) (string, error) {
	renderer := NewRenderer(nil)
	return renderer.RenderFile(ctx, templatePath, data, DefaultRenderOptions())
}
