// Package parse defines domain interfaces for data parsing and transformation operations
package parse

import (
	"context"
	"io"
)

// ParseService provides the main domain service for data parsing operations
type ParseService interface {
	// JSON operations
	ParseJSON(ctx context.Context, input string) (*ParsedData, error)
	ParseJSONFromReader(ctx context.Context, reader io.Reader) (*ParsedData, error)
	FormatJSON(ctx context.Context, data interface{}, pretty bool) (string, error)

	// YAML operations
	ParseYAML(ctx context.Context, input string) (*ParsedData, error)
	ParseYAMLFromReader(ctx context.Context, reader io.Reader) (*ParsedData, error)
	FormatYAML(ctx context.Context, data interface{}) (string, error)

	// XML operations
	ParseXML(ctx context.Context, input string) (*ParsedData, error)
	ParseXMLFromReader(ctx context.Context, reader io.Reader) (*ParsedData, error)
	FormatXML(ctx context.Context, data interface{}, pretty bool) (string, error)

	// CSV operations
	ParseCSV(ctx context.Context, input string, config *CSVConfig) (*ParsedData, error)
	ParseCSVFromReader(ctx context.Context, reader io.Reader, config *CSVConfig) (*ParsedData, error)
	FormatCSV(ctx context.Context, data []map[string]interface{}, config *CSVConfig) (string, error)

	// TOML operations
	ParseTOML(ctx context.Context, input string) (*ParsedData, error)
	FormatTOML(ctx context.Context, data interface{}) (string, error)

	// INI operations
	ParseINI(ctx context.Context, input string) (*ParsedData, error)
	FormatINI(ctx context.Context, data map[string]map[string]string) (string, error)

	// Generic operations
	DetectFormat(ctx context.Context, input string) (DataFormat, float64, error)
	Convert(ctx context.Context, input string, fromFormat, toFormat DataFormat, options *ConvertOptions) (string, error)
	Validate(ctx context.Context, input string, format DataFormat, schema interface{}) (*ValidationResult, error)

	// Transformation operations
	Transform(ctx context.Context, data *ParsedData, transformer DataTransformer) (*ParsedData, error)
	ExtractFields(ctx context.Context, data *ParsedData, fields []string) (*ParsedData, error)
	FilterData(ctx context.Context, data *ParsedData, filter DataFilter) (*ParsedData, error)

	// Batch operations
	ParseMultiple(ctx context.Context, inputs []string, format DataFormat) ([]*ParsedData, error)
	MergeData(ctx context.Context, datasets []*ParsedData, strategy MergeStrategy) (*ParsedData, error)
}

// JSONParser provides JSON-specific parsing operations
type JSONParser interface {
	Parse(ctx context.Context, input string) (map[string]interface{}, error)
	ParseArray(ctx context.Context, input string) ([]interface{}, error)
	ParseToStruct(ctx context.Context, input string, target interface{}) error
	Format(ctx context.Context, data interface{}, pretty bool) (string, error)
	Validate(ctx context.Context, input string, schema interface{}) error
	ExtractPath(ctx context.Context, input string, jsonPath string) (interface{}, error)
}

// YAMLParser provides YAML-specific parsing operations
type YAMLParser interface {
	Parse(ctx context.Context, input string) (map[string]interface{}, error)
	ParseMultiDocument(ctx context.Context, input string) ([]map[string]interface{}, error)
	ParseToStruct(ctx context.Context, input string, target interface{}) error
	Format(ctx context.Context, data interface{}) (string, error)
	Validate(ctx context.Context, input string, schema interface{}) error
	ConvertToJSON(ctx context.Context, input string) (string, error)
}

// XMLParser provides XML-specific parsing operations
type XMLParser interface {
	Parse(ctx context.Context, input string) (map[string]interface{}, error)
	ParseToStruct(ctx context.Context, input string, target interface{}) error
	Format(ctx context.Context, data interface{}, pretty bool) (string, error)
	Validate(ctx context.Context, input string, xsd interface{}) error
	ExtractXPath(ctx context.Context, input string, xpath string) ([]interface{}, error)
	ConvertToJSON(ctx context.Context, input string) (string, error)
}

// CSVParser provides CSV-specific parsing operations
type CSVParser interface {
	Parse(ctx context.Context, input string, config *CSVConfig) ([]map[string]interface{}, error)
	ParseToStructs(ctx context.Context, input string, config *CSVConfig, target interface{}) error
	Format(ctx context.Context, data []map[string]interface{}, config *CSVConfig) (string, error)
	Validate(ctx context.Context, input string, config *CSVConfig) error
	DetectDelimiter(ctx context.Context, input string) (rune, error)
	ExtractColumns(ctx context.Context, input string, columns []string, config *CSVConfig) ([]map[string]interface{}, error)
}

// TOMLParser provides TOML-specific parsing operations
type TOMLParser interface {
	Parse(ctx context.Context, input string) (map[string]interface{}, error)
	ParseToStruct(ctx context.Context, input string, target interface{}) error
	Format(ctx context.Context, data interface{}) (string, error)
	Validate(ctx context.Context, input string) error
	ConvertToJSON(ctx context.Context, input string) (string, error)
}

// INIParser provides INI-specific parsing operations
type INIParser interface {
	Parse(ctx context.Context, input string) (map[string]map[string]string, error)
	Format(ctx context.Context, data map[string]map[string]string) (string, error)
	GetSection(ctx context.Context, input string, section string) (map[string]string, error)
	SetValue(ctx context.Context, input string, section, key, value string) (string, error)
	RemoveKey(ctx context.Context, input string, section, key string) (string, error)
}

// FormatDetector detects data formats from input
type FormatDetector interface {
	DetectFormat(ctx context.Context, input string) (DataFormat, float64, error)
	DetectFromBytes(ctx context.Context, data []byte) (DataFormat, float64, error)
	DetectFromReader(ctx context.Context, reader io.Reader) (DataFormat, float64, error)
	DetectFromFilename(filename string) (DataFormat, float64, error)
	SupportedFormats() []DataFormat
}

// DataValidator validates parsed data against schemas
type DataValidator interface {
	ValidateJSON(ctx context.Context, data interface{}, schema interface{}) (*ValidationResult, error)
	ValidateYAML(ctx context.Context, data interface{}, schema interface{}) (*ValidationResult, error)
	ValidateXML(ctx context.Context, data interface{}, xsd interface{}) (*ValidationResult, error)
	ValidateCSV(ctx context.Context, data []map[string]interface{}, rules *CSVValidationRules) (*ValidationResult, error)
	CreateSchema(ctx context.Context, samples []interface{}, format DataFormat) (interface{}, error)
}

// DataTransformer transforms parsed data
type DataTransformer interface {
	Transform(ctx context.Context, data *ParsedData) (*ParsedData, error)
	GetName() string
	GetDescription() string
}

// DataFilter filters parsed data
type DataFilter interface {
	Filter(ctx context.Context, data *ParsedData) (*ParsedData, error)
	GetCriteria() string
}

// DataConverter converts between formats
type DataConverter interface {
	Convert(ctx context.Context, input string, fromFormat, toFormat DataFormat, options *ConvertOptions) (string, error)
	SupportedConversions() map[DataFormat][]DataFormat
	ConvertWithSchema(ctx context.Context, input string, fromFormat, toFormat DataFormat, schema interface{}, options *ConvertOptions) (string, error)
}

// ParseRepository manages parsed data persistence
type ParseRepository interface {
	SaveParsedData(ctx context.Context, data *ParsedData) error
	GetParsedData(ctx context.Context, id string) (*ParsedData, error)
	ListParsedData(ctx context.Context, filter *ParseFilter) ([]*ParsedData, error)
	DeleteParsedData(ctx context.Context, id string) error
	UpdateParsedData(ctx context.Context, id string, data *ParsedData) error
}

// ParseAuditRepository tracks parsing operations
type ParseAuditRepository interface {
	RecordParseOperation(ctx context.Context, operation *ParseOperation) error
	GetParseHistory(ctx context.Context, filter *ParseAuditFilter) ([]*ParseOperation, error)
	GetParseStatistics(ctx context.Context, timeRange *TimeRange) (*ParseStatistics, error)
}