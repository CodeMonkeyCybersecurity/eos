// Package fileops provides template operations infrastructure
package fileops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/fileops"
	"go.uber.org/zap"
)

// TemplateOperationsImpl implements fileops.TemplateOperations
type TemplateOperationsImpl struct {
	fileOps fileops.FileOperations
	logger  *zap.Logger
}

// NewTemplateOperations creates a new template operations implementation
func NewTemplateOperations(fileOps fileops.FileOperations, logger *zap.Logger) *TemplateOperationsImpl {
	return &TemplateOperationsImpl{
		fileOps: fileOps,
		logger:  logger,
	}
}

// ReplaceTokensInFile replaces tokens in a file
func (t *TemplateOperationsImpl) ReplaceTokensInFile(ctx context.Context, path string, replacements map[string]string) error {
	// Read file content
	content, err := t.fileOps.ReadFile(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", path, err)
	}

	// Convert to string for processing
	text := string(content)
	originalText := text

	// Replace tokens
	for token, value := range replacements {
		// Support different token formats
		text = strings.ReplaceAll(text, "{{"+token+"}}", value)
		text = strings.ReplaceAll(text, "${"+token+"}", value)
		text = strings.ReplaceAll(text, "__"+token+"__", value)
	}

	// Only write if content changed
	if text != originalText {
		// Get original file permissions
		info, err := t.fileOps.GetFileInfo(ctx, path)
		if err != nil {
			return fmt.Errorf("failed to get file info: %w", err)
		}

		// Write updated content
		if err := t.fileOps.WriteFile(ctx, path, []byte(text), info.Mode()); err != nil {
			return fmt.Errorf("failed to write file %s: %w", path, err)
		}

		t.logger.Info("Tokens replaced in file",
			zap.String("path", path),
			zap.Int("replacements", len(replacements)),
		)
	}

	return nil
}

// ReplaceTokensInDirectory replaces tokens in all files in a directory
func (t *TemplateOperationsImpl) ReplaceTokensInDirectory(ctx context.Context, dir string, replacements map[string]string, patterns []string) error {
	// Default patterns if none provided
	if len(patterns) == 0 {
		patterns = []string{"*"}
	}

	// Walk directory
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check if file matches any pattern
		matched := false
		baseName := filepath.Base(path)
		for _, pattern := range patterns {
			if ok, _ := filepath.Match(pattern, baseName); ok {
				matched = true
				break
			}
		}

		if !matched {
			return nil
		}

		// Process file
		if err := t.ReplaceTokensInFile(ctx, path, replacements); err != nil {
			t.logger.Warn("Failed to replace tokens in file",
				zap.String("path", path),
				zap.Error(err),
			)
			// Continue with other files
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk directory %s: %w", dir, err)
	}

	t.logger.Info("Token replacement completed",
		zap.String("directory", dir),
		zap.Int("patterns", len(patterns)),
		zap.Int("replacements", len(replacements)),
	)

	return nil
}

// ProcessTemplate processes a template file with the given data
func (t *TemplateOperationsImpl) ProcessTemplate(ctx context.Context, templatePath, outputPath string, data interface{}) error {
	// Read template content
	templateContent, err := t.fileOps.ReadFile(ctx, templatePath)
	if err != nil {
		return fmt.Errorf("failed to read template file %s: %w", templatePath, err)
	}

	// Parse template
	tmpl, err := template.New(filepath.Base(templatePath)).Parse(string(templateContent))
	if err != nil {
		return fmt.Errorf("failed to parse template %s: %w", templatePath, err)
	}

	// Create output file
	file, err := t.fileOps.OpenFile(ctx, outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", outputPath, err)
	}
	defer file.Close()

	// Execute template
	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	t.logger.Info("Template processed successfully",
		zap.String("template", templatePath),
		zap.String("output", outputPath),
	)

	return nil
}

// Ensure interface is implemented
var _ fileops.TemplateOperations = (*TemplateOperationsImpl)(nil)