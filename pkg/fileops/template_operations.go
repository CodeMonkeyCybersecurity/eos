// pkg/domain/fileops/template_operations.go

package fileops

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

const (
	// SECURITY: Maximum template size to prevent resource exhaustion
	MaxTemplateSize = 1 * 1024 * 1024 // 1MB
	// SECURITY: Timeout for template execution to prevent infinite loops
	TemplateExecutionTimeout = 30 * time.Second
	// SECURITY: Rate limit burst for template operations
	TemplateRateBurst = 5
)

var (
	// SECURITY: Rate limit for template operations (10 per minute)
	TemplateRateLimit = rate.Every(time.Minute / 10)
)

// TemplateOperations provides template rendering operations
type TemplateOperations struct {
	fileOps     *FileSystemOperations
	pathOps     *PathOperations
	logger      *zap.Logger
	rateLimiter *rate.Limiter
	limiterMu   sync.Mutex
}

// NewTemplateOperations creates a new template operations implementation
func NewTemplateOperations(fileOps *FileSystemOperations, pathOps *PathOperations, logger *zap.Logger) *TemplateOperations {
	return &TemplateOperations{
		fileOps:     fileOps,
		pathOps:     pathOps,
		logger:      logger.Named("template"),
		rateLimiter: rate.NewLimiter(TemplateRateLimit, TemplateRateBurst),
	}
}

// ReplaceTokensInFile replaces tokens in a file
func (t *TemplateOperations) ReplaceTokensInFile(ctx context.Context, path string, replacements map[string]string) error {
	t.logger.Debug("Replacing tokens in file",
		zap.String("path", path),
		zap.Int("replacements", len(replacements)))

	// Read file content
	content, err := t.fileOps.ReadFile(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Replace tokens
	contentStr := string(content)
	for token, value := range replacements {
		// Support both ${TOKEN} and {{TOKEN}} formats
		contentStr = strings.ReplaceAll(contentStr, "${"+token+"}", value)
		contentStr = strings.ReplaceAll(contentStr, "{{"+token+"}}", value)
		contentStr = strings.ReplaceAll(contentStr, "[["+token+"]]", value)
	}

	// Write back
	if err := t.fileOps.WriteFile(ctx, path, []byte(contentStr), 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	t.logger.Info("Tokens replaced successfully",
		zap.String("path", path))

	return nil
}

// ReplaceTokensInDirectory replaces tokens in all files in a directory
func (t *TemplateOperations) ReplaceTokensInDirectory(ctx context.Context, dir string, replacements map[string]string, patterns []string) error {
	t.logger.Info("Replacing tokens in directory",
		zap.String("dir", dir),
		zap.Strings("patterns", patterns))

	// List all files in directory
	entries, err := t.fileOps.ListDirectory(ctx, dir)
	if err != nil {
		return fmt.Errorf("failed to list directory: %w", err)
	}

	processedCount := 0
	for _, entry := range entries {
		// SECURITY: Check for context cancellation in loop
		select {
		case <-ctx.Done():
			t.logger.Warn("Token replacement cancelled",
				zap.String("dir", dir),
				zap.Int("files_processed", processedCount),
				zap.Error(ctx.Err()))
			return fmt.Errorf("operation cancelled: %w", ctx.Err())
		default:
			// Continue processing
		}

		if entry.IsDir() {
			continue
		}

		path := t.pathOps.JoinPath(dir, entry.Name())

		// Check if file matches patterns
		if len(patterns) > 0 {
			matched := false
			for _, pattern := range patterns {
				if match, _ := filepath.Match(pattern, entry.Name()); match {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// Process file
		if err := t.ReplaceTokensInFile(ctx, path, replacements); err != nil {
			t.logger.Warn("Failed to process file",
				zap.String("path", path),
				zap.Error(err))
			continue
		}

		processedCount++
	}

	t.logger.Info("Directory token replacement completed",
		zap.String("dir", dir),
		zap.Int("files_processed", processedCount))

	return nil
}

// ProcessTemplate processes a template file with the given data
func (t *TemplateOperations) ProcessTemplate(ctx context.Context, templatePath, outputPath string, data interface{}) error {
	// SECURITY: Apply rate limiting to prevent DoS via rapid template operations
	t.limiterMu.Lock()
	if !t.rateLimiter.Allow() {
		t.limiterMu.Unlock()
		t.logger.Warn("Template operation rate limit exceeded",
			zap.String("template", templatePath))
		return fmt.Errorf("rate limit exceeded for template operations")
	}
	t.limiterMu.Unlock()

	t.logger.Debug("Processing template",
		zap.String("template", templatePath),
		zap.String("output", outputPath))

	// SECURITY: Validate template path (prevent directory traversal)
	if !filepath.IsAbs(templatePath) {
		// SECURITY: Sanitize error message in production (don't leak path details)
		if os.Getenv("GO_ENV") == "production" {
			return fmt.Errorf("template path must be absolute")
		}
		return fmt.Errorf("template path must be absolute: %s", templatePath)
	}

	// SECURITY: Check template size to prevent resource exhaustion
	templateInfo, err := t.fileOps.GetFileInfo(ctx, templatePath)
	if err != nil {
		// SECURITY: Sanitize error message in production
		if os.Getenv("GO_ENV") == "production" {
			return fmt.Errorf("failed to access template file")
		}
		return fmt.Errorf("failed to get template info for %s: %w", templatePath, err)
	}
	if templateInfo.Size() > MaxTemplateSize {
		t.logger.Error("Template too large",
			zap.String("template", templatePath),
			zap.Int64("size", templateInfo.Size()),
			zap.Int64("max_size", MaxTemplateSize))
		return fmt.Errorf("template too large: %d bytes (max %d)", templateInfo.Size(), MaxTemplateSize)
	}

	// Read template file
	templateContent, err := t.fileOps.ReadFile(ctx, templatePath)
	if err != nil {
		return fmt.Errorf("failed to read template: %w", err)
	}

	// SECURITY: Parse template with strict settings
	tmpl := template.New(t.pathOps.BaseName(templatePath))
	tmpl.Option("missingkey=error") // Fail on missing keys instead of silent <no value>

	tmpl, err = tmpl.Parse(string(templateContent))
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// SECURITY: Execute template with timeout to prevent infinite loops
	var buf bytes.Buffer
	executionDone := make(chan error, 1)

	shared.SafeGo(t.logger, "template-execution", func() {
		executionDone <- tmpl.Execute(&buf, data)
	})

	select {
	case err := <-executionDone:
		if err != nil {
			return fmt.Errorf("failed to execute template: %w", err)
		}
	case <-time.After(TemplateExecutionTimeout):
		t.logger.Error("Template execution timeout",
			zap.String("template", templatePath),
			zap.Duration("timeout", TemplateExecutionTimeout))
		return fmt.Errorf("template execution timeout after %v", TemplateExecutionTimeout)
	case <-ctx.Done():
		return fmt.Errorf("template execution cancelled: %w", ctx.Err())
	}

	// SECURITY: Validate output size before writing (allow 10x expansion)
	if buf.Len() > MaxTemplateSize*10 {
		t.logger.Error("Template output too large",
			zap.String("template", templatePath),
			zap.Int("output_size", buf.Len()))
		return fmt.Errorf("template output too large: %d bytes", buf.Len())
	}

	// SECURITY: Write output with restrictive permissions (0640 instead of 0644)
	if err := t.fileOps.WriteFile(ctx, outputPath, buf.Bytes(), 0640); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	// SECURITY: Audit log for sensitive template operations
	t.logger.Info("AUDIT: Template processed",
		zap.String("template", templatePath),
		zap.String("output", outputPath),
		zap.Int("output_size", buf.Len()),
		zap.String("user", os.Getenv("SUDO_USER")),
		zap.Time("timestamp", time.Now()))

	return nil
}
