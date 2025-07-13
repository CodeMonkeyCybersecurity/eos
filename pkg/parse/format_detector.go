// Package parse provides infrastructure implementations for parsing operations
package parse

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// FormatDetectorImpl implements the FormatDetector interface
type FormatDetectorImpl struct {
	logger *zap.Logger
}

// NewFormatDetector creates a new format detector implementation
func NewFormatDetector(logger *zap.Logger) *FormatDetectorImpl {
	return &FormatDetectorImpl{
		logger: logger,
	}
}

// DetectFormat detects the format of input data
func (f *FormatDetectorImpl) DetectFormat(ctx context.Context, input string) (parse.DataFormat, float64, error) {
	input = strings.TrimSpace(input)

	if input == "" {
		return parse.FormatUnknown, 0.0, nil
	}

	// Try each format detection method
	detectors := []struct {
		format   parse.DataFormat
		detector func(string) float64
	}{
		{parse.FormatJSON, f.detectJSON},
		{parse.FormatXML, f.detectXML},
		{parse.FormatYAML, f.detectYAML},
		{parse.FormatCSV, f.detectCSV},
		{parse.FormatTOML, f.detectTOML},
		{parse.FormatINI, f.detectINI},
	}

	bestFormat := parse.FormatUnknown
	bestConfidence := 0.0

	for _, detector := range detectors {
		confidence := detector.detector(input)
		if confidence > bestConfidence {
			bestConfidence = confidence
			bestFormat = detector.format
		}
	}

	f.logger.Info("Format detection completed",
		zap.String("detected_format", string(bestFormat)),
		zap.Float64("confidence", bestConfidence))

	return bestFormat, bestConfidence, nil
}

// DetectFromBytes detects format from byte data
func (f *FormatDetectorImpl) DetectFromBytes(ctx context.Context, data []byte) (parse.DataFormat, float64, error) {
	return f.DetectFormat(ctx, string(data))
}

// DetectFromReader detects format from an io.Reader
func (f *FormatDetectorImpl) DetectFromReader(ctx context.Context, reader io.Reader) (parse.DataFormat, float64, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return parse.FormatUnknown, 0.0, err
	}

	return f.DetectFormat(ctx, string(data))
}

// DetectFromFilename detects format from filename extension
func (f *FormatDetectorImpl) DetectFromFilename(filename string) (parse.DataFormat, float64, error) {
	ext := strings.ToLower(filepath.Ext(filename))

	switch ext {
	case ".json":
		return parse.FormatJSON, 1.0, nil
	case ".yaml", ".yml":
		return parse.FormatYAML, 1.0, nil
	case ".xml":
		return parse.FormatXML, 1.0, nil
	case ".csv":
		return parse.FormatCSV, 1.0, nil
	case ".toml":
		return parse.FormatTOML, 1.0, nil
	case ".ini", ".cfg", ".conf":
		return parse.FormatINI, 1.0, nil
	case ".tsv":
		return parse.FormatTSV, 1.0, nil
	case ".html", ".htm":
		return parse.FormatHTML, 1.0, nil
	case ".txt":
		return parse.FormatTXT, 0.5, nil
	default:
		return parse.FormatUnknown, 0.0, nil
	}
}

// SupportedFormats returns the list of supported formats
func (f *FormatDetectorImpl) SupportedFormats() []parse.DataFormat {
	return []parse.DataFormat{
		parse.FormatJSON,
		parse.FormatYAML,
		parse.FormatXML,
		parse.FormatCSV,
		parse.FormatTOML,
		parse.FormatINI,
		parse.FormatTSV,
		parse.FormatHTML,
		parse.FormatTXT,
	}
}

// detectJSON attempts to detect JSON format
func (f *FormatDetectorImpl) detectJSON(input string) float64 {
	input = strings.TrimSpace(input)

	// Quick structural checks
	if (!strings.HasPrefix(input, "{") || !strings.HasSuffix(input, "}")) &&
		(!strings.HasPrefix(input, "[") || !strings.HasSuffix(input, "]")) {
		return 0.0
	}

	// Try to parse as JSON
	var temp interface{}
	if err := json.Unmarshal([]byte(input), &temp); err != nil {
		return 0.0
	}

	// Additional heuristics for confidence
	confidence := 0.8

	// Check for JSON-specific patterns
	if strings.Contains(input, `"`) && strings.Contains(input, `:`) {
		confidence += 0.15
	}

	// Check for common JSON structures
	if regexp.MustCompile(`"[^"]+"\s*:\s*`).MatchString(input) {
		confidence += 0.05
	}

	return confidence
}

// detectXML attempts to detect XML format
func (f *FormatDetectorImpl) detectXML(input string) float64 {
	input = strings.TrimSpace(input)

	// Quick structural checks
	if !strings.HasPrefix(input, "<") || !strings.HasSuffix(input, ">") {
		return 0.0
	}

	// Try to parse as XML
	var temp interface{}
	if err := xml.Unmarshal([]byte(input), &temp); err != nil {
		return 0.0
	}

	confidence := 0.8

	// Check for XML declaration
	if strings.HasPrefix(input, "<?xml") {
		confidence += 0.15
	}

	// Check for namespace declarations
	if strings.Contains(input, "xmlns") {
		confidence += 0.05
	}

	return confidence
}

// detectYAML attempts to detect YAML format
func (f *FormatDetectorImpl) detectYAML(input string) float64 {
	input = strings.TrimSpace(input)

	// Try to parse as YAML
	var temp interface{}
	if err := yaml.Unmarshal([]byte(input), &temp); err != nil {
		return 0.0
	}

	// If it also parses as JSON, it's probably JSON
	var jsonTemp interface{}
	if json.Unmarshal([]byte(input), &jsonTemp) == nil {
		// Check if it has JSON-specific syntax
		if strings.Contains(input, "{") && strings.Contains(input, "}") {
			return 0.1 // Low confidence, likely JSON
		}
	}

	confidence := 0.7

	// Check for YAML-specific patterns
	if strings.Contains(input, "---") { // Document separator
		confidence += 0.2
	}

	// Check for key-value pairs with colons but no quotes
	yamlPattern := regexp.MustCompile(`^\s*[^"'\s]+\s*:\s*[^"'\s]`)
	if yamlPattern.MatchString(input) {
		confidence += 0.1
	}

	// Check for list syntax
	if strings.Contains(input, "- ") {
		confidence += 0.05
	}

	return confidence
}

// detectCSV attempts to detect CSV format
func (f *FormatDetectorImpl) detectCSV(input string) float64 {
	lines := strings.Split(input, "\n")
	if len(lines) < 2 {
		return 0.0
	}

	// Check for consistent delimiter usage
	delimiters := []rune{',', ';', '\t', '|'}

	for _, delimiter := range delimiters {
		confidence := f.checkCSVDelimiter(lines, delimiter)
		if confidence > 0.5 {
			return confidence
		}
	}

	return 0.0
}

// checkCSVDelimiter checks if lines consistently use a specific delimiter
func (f *FormatDetectorImpl) checkCSVDelimiter(lines []string, delimiter rune) float64 {
	if len(lines) < 2 {
		return 0.0
	}

	// Count columns in first line
	firstLineColumns := strings.Count(lines[0], string(delimiter)) + 1
	if firstLineColumns < 2 {
		return 0.0
	}

	consistentLines := 0
	totalLines := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		totalLines++
		lineColumns := strings.Count(line, string(delimiter)) + 1

		// Allow some variance for CSV files with optional fields
		if lineColumns == firstLineColumns || lineColumns == firstLineColumns-1 {
			consistentLines++
		}
	}

	if totalLines == 0 {
		return 0.0
	}

	consistency := float64(consistentLines) / float64(totalLines)

	if consistency >= 0.8 {
		return 0.7 + (consistency-0.8)*0.3 // Scale from 0.7 to 1.0
	}

	return 0.0
}

// detectTOML attempts to detect TOML format
func (f *FormatDetectorImpl) detectTOML(input string) float64 {
	// Look for TOML-specific patterns
	confidence := 0.0

	// Check for section headers [section]
	sectionPattern := regexp.MustCompile(`^\s*\[[^\]]+\]\s*$`)
	if sectionPattern.MatchString(input) {
		confidence += 0.4
	}

	// Check for key = value patterns
	keyValuePattern := regexp.MustCompile(`^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*.+$`)
	lines := strings.Split(input, "\n")
	keyValueLines := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if keyValuePattern.MatchString(line) {
			keyValueLines++
		}
	}

	if keyValueLines > 0 {
		confidence += 0.3
	}

	// Check for TOML-specific value types
	if strings.Contains(input, "[[") || strings.Contains(input, "]]") {
		confidence += 0.2
	}

	// Check for datetime format
	datetimePattern := regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`)
	if datetimePattern.MatchString(input) {
		confidence += 0.1
	}

	return confidence
}

// detectINI attempts to detect INI format
func (f *FormatDetectorImpl) detectINI(input string) float64 {
	lines := strings.Split(input, "\n")

	hasSections := false
	hasKeyValues := false

	sectionPattern := regexp.MustCompile(`^\s*\[[^\]]+\]\s*$`)
	keyValuePattern := regexp.MustCompile(`^\s*[^=\s]+\s*=\s*.+$`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		if sectionPattern.MatchString(line) {
			hasSections = true
		} else if keyValuePattern.MatchString(line) {
			hasKeyValues = true
		}
	}

	if hasSections && hasKeyValues {
		return 0.8
	} else if hasKeyValues {
		return 0.5
	}

	return 0.0
}
