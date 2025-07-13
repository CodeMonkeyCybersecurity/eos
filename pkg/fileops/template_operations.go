// pkg/domain/fileops/template_operations.go

package fileops

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"text/template"

	"go.uber.org/zap"
)

// TemplateOperations provides template rendering operations
type TemplateOperations struct {
	fileOps *FileSystemOperations
	pathOps *PathOperations
	logger  *zap.Logger
}

// NewTemplateOperations creates a new template operations implementation
func NewTemplateOperations(fileOps *FileSystemOperations, pathOps *PathOperations, logger *zap.Logger) *TemplateOperations {
	return &TemplateOperations{
		fileOps: fileOps,
		pathOps: pathOps,
		logger:  logger.Named("template"),
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
	t.logger.Debug("Processing template",
		zap.String("template", templatePath),
		zap.String("output", outputPath))

	// Read template file
	templateContent, err := t.fileOps.ReadFile(ctx, templatePath)
	if err != nil {
		return fmt.Errorf("failed to read template: %w", err)
	}

	// Parse template
	tmpl, err := template.New(t.pathOps.BaseName(templatePath)).Parse(string(templateContent))
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	// Write output
	if err := t.fileOps.WriteFile(ctx, outputPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	t.logger.Info("Template processed successfully",
		zap.String("template", templatePath),
		zap.String("output", outputPath))

	return nil
}
