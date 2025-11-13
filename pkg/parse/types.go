// Package parse provides data format parsing and detection capabilities
package parse

import (
	"context"
	"io"
)

// DataFormat represents a supported data format
type DataFormat string

const (
	FormatUnknown DataFormat = "unknown"
	FormatJSON    DataFormat = "json"
	FormatYAML    DataFormat = "yaml"
	FormatXML     DataFormat = "xml"
	FormatCSV     DataFormat = "csv"
	FormatTSV     DataFormat = "tsv"
	FormatTOML    DataFormat = "toml"
	FormatINI     DataFormat = "ini"
	FormatHTML    DataFormat = "html"
	FormatTXT     DataFormat = "txt"
)

// String returns the string representation of the data format
func (f DataFormat) String() string {
	return string(f)
}

// FormatDetector defines the interface for format detection
type FormatDetector interface {
	// DetectFormat detects the format of input data
	DetectFormat(ctx context.Context, input string) (DataFormat, float64, error)

	// DetectFromBytes detects format from byte data
	DetectFromBytes(ctx context.Context, data []byte) (DataFormat, float64, error)

	// DetectFromReader detects format from an io.Reader
	DetectFromReader(ctx context.Context, reader io.Reader) (DataFormat, float64, error)

	// DetectFromFilename detects format from filename extension
	DetectFromFilename(filename string) (DataFormat, float64, error)

	// SupportedFormats returns the list of supported formats
	SupportedFormats() []DataFormat
}

// Parser defines the interface for parsing data
type Parser interface {
	// Parse parses input data into a structured format
	Parse(ctx context.Context, input string, format DataFormat) (interface{}, error)

	// ParseBytes parses byte data into a structured format
	ParseBytes(ctx context.Context, data []byte, format DataFormat) (interface{}, error)

	// ParseReader parses data from an io.Reader into a structured format
	ParseReader(ctx context.Context, reader io.Reader, format DataFormat) (interface{}, error)
}

// FormatConverter defines the interface for converting between formats
type FormatConverter interface {
	// Convert converts data from one format to another
	Convert(ctx context.Context, input string, fromFormat, toFormat DataFormat) (string, error)

	// ConvertBytes converts byte data from one format to another
	ConvertBytes(ctx context.Context, data []byte, fromFormat, toFormat DataFormat) ([]byte, error)
}

// ValidationError represents a data validation error
type ValidationError struct {
	Field   string
	Message string
	Value   interface{}
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	return e.Message
}

// ParseResult represents the result of a parsing operation
type ParseResult struct {
	Data   interface{}
	Format DataFormat
	Errors []ValidationError
}

// DetectionResult represents the result of format detection
type DetectionResult struct {
	Format     DataFormat
	Confidence float64
	Metadata   map[string]interface{}
}
