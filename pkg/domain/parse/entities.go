// Package parse defines domain entities for data parsing and transformation
package parse

import (
	"time"
)

// Core parsing entities

// ParsedData represents the result of a parsing operation
type ParsedData struct {
	ID           string                 `json:"id"`
	OriginalData string                 `json:"original_data,omitempty"`
	ParsedValue  interface{}            `json:"parsed_value"`
	Format       DataFormat             `json:"format"`
	Metadata     *ParseMetadata         `json:"metadata"`
	Schema       interface{}            `json:"schema,omitempty"`
	Errors       []*ParseError          `json:"errors,omitempty"`
	Warnings     []*ParseWarning        `json:"warnings,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	Tags         map[string]string      `json:"tags,omitempty"`
	Source       *DataSource            `json:"source,omitempty"`
}

// ParseMetadata contains metadata about the parsing operation
type ParseMetadata struct {
	Size           int64             `json:"size"`
	LineCount      int               `json:"line_count,omitempty"`
	ColumnCount    int               `json:"column_count,omitempty"`
	RecordCount    int               `json:"record_count,omitempty"`
	ParseDuration  time.Duration     `json:"parse_duration"`
	Parser         string            `json:"parser"`
	ParserVersion  string            `json:"parser_version"`
	Encoding       string            `json:"encoding"`
	Compression    CompressionType   `json:"compression,omitempty"`
	Checksum       string            `json:"checksum,omitempty"`
	CustomFields   map[string]string `json:"custom_fields,omitempty"`
}

// DataSource represents the source of parsed data
type DataSource struct {
	Type        SourceType `json:"type"`
	Location    string     `json:"location"`
	Filename    string     `json:"filename,omitempty"`
	ContentType string     `json:"content_type,omitempty"`
	Size        int64      `json:"size,omitempty"`
	LastModified *time.Time `json:"last_modified,omitempty"`
}

// ParseError represents an error that occurred during parsing
type ParseError struct {
	Code        string    `json:"code"`
	Message     string    `json:"message"`
	Line        int       `json:"line,omitempty"`
	Column      int       `json:"column,omitempty"`
	Position    int64     `json:"position,omitempty"`
	Context     string    `json:"context,omitempty"`
	Severity    Severity  `json:"severity"`
	Recoverable bool      `json:"recoverable"`
	Timestamp   time.Time `json:"timestamp"`
}

// ParseWarning represents a warning that occurred during parsing
type ParseWarning struct {
	Code      string    `json:"code"`
	Message   string    `json:"message"`
	Line      int       `json:"line,omitempty"`
	Column    int       `json:"column,omitempty"`
	Context   string    `json:"context,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Configuration entities

// CSVConfig defines configuration for CSV parsing
type CSVConfig struct {
	Delimiter        rune   `json:"delimiter"`
	Comment          rune   `json:"comment,omitempty"`
	Quote            rune   `json:"quote"`
	Escape           rune   `json:"escape,omitempty"`
	HasHeader        bool   `json:"has_header"`
	SkipLines        int    `json:"skip_lines"`
	MaxRecords       int    `json:"max_records,omitempty"`
	TrimSpace        bool   `json:"trim_space"`
	AllowQuotes      bool   `json:"allow_quotes"`
	StrictQuotes     bool   `json:"strict_quotes"`
	Headers          []string `json:"headers,omitempty"`
	ColumnTypes      map[string]DataType `json:"column_types,omitempty"`
	NullValues       []string `json:"null_values,omitempty"`
	DateFormat       string   `json:"date_format,omitempty"`
	TimeFormat       string   `json:"time_format,omitempty"`
}

// ConvertOptions defines options for format conversion
type ConvertOptions struct {
	Pretty           bool              `json:"pretty"`
	Indent           string            `json:"indent,omitempty"`
	PreserveOrder    bool              `json:"preserve_order"`
	StrictMode       bool              `json:"strict_mode"`
	IgnoreErrors     bool              `json:"ignore_errors"`
	CustomMappings   map[string]string `json:"custom_mappings,omitempty"`
	SchemaValidation bool              `json:"schema_validation"`
	Encoding         string            `json:"encoding,omitempty"`
	LineEnding       LineEndingType    `json:"line_ending,omitempty"`
}

// Validation entities

// ValidationResult represents the result of data validation
type ValidationResult struct {
	Valid        bool                `json:"valid"`
	Errors       []*ValidationError  `json:"errors,omitempty"`
	Warnings     []*ValidationWarning `json:"warnings,omitempty"`
	Score        float64             `json:"score"`
	Schema       interface{}         `json:"schema,omitempty"`
	ValidatedAt  time.Time           `json:"validated_at"`
	Validator    string              `json:"validator"`
	Statistics   *ValidationStats    `json:"statistics,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Code        string      `json:"code"`
	Message     string      `json:"message"`
	Path        string      `json:"path,omitempty"`
	Value       interface{} `json:"value,omitempty"`
	Expected    interface{} `json:"expected,omitempty"`
	Constraint  string      `json:"constraint,omitempty"`
	Severity    Severity    `json:"severity"`
	Line        int         `json:"line,omitempty"`
	Column      int         `json:"column,omitempty"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Code     string      `json:"code"`
	Message  string      `json:"message"`
	Path     string      `json:"path,omitempty"`
	Value    interface{} `json:"value,omitempty"`
	Suggestion string    `json:"suggestion,omitempty"`
	Line     int         `json:"line,omitempty"`
	Column   int         `json:"column,omitempty"`
}

// ValidationStats contains validation statistics
type ValidationStats struct {
	TotalFields    int `json:"total_fields"`
	ValidFields    int `json:"valid_fields"`
	InvalidFields  int `json:"invalid_fields"`
	MissingFields  int `json:"missing_fields"`
	ExtraFields    int `json:"extra_fields"`
	TotalRecords   int `json:"total_records"`
	ValidRecords   int `json:"valid_records"`
	InvalidRecords int `json:"invalid_records"`
}

// CSVValidationRules defines validation rules for CSV data
type CSVValidationRules struct {
	RequiredColumns  []string                    `json:"required_columns"`
	ColumnTypes      map[string]DataType         `json:"column_types"`
	ColumnConstraints map[string]*ColumnConstraint `json:"column_constraints"`
	UniqueColumns    []string                    `json:"unique_columns"`
	MinRows          int                         `json:"min_rows"`
	MaxRows          int                         `json:"max_rows"`
	AllowEmptyValues bool                        `json:"allow_empty_values"`
	CustomValidators map[string]string           `json:"custom_validators,omitempty"`
}

// ColumnConstraint defines constraints for a column
type ColumnConstraint struct {
	MinLength    int      `json:"min_length,omitempty"`
	MaxLength    int      `json:"max_length,omitempty"`
	Pattern      string   `json:"pattern,omitempty"`
	EnumValues   []string `json:"enum_values,omitempty"`
	MinValue     float64  `json:"min_value,omitempty"`
	MaxValue     float64  `json:"max_value,omitempty"`
	Required     bool     `json:"required"`
	Unique       bool     `json:"unique"`
	Format       string   `json:"format,omitempty"`
}

// Operation tracking entities

// ParseOperation represents a parsing operation for audit purposes
type ParseOperation struct {
	ID            string                 `json:"id"`
	UserID        string                 `json:"user_id,omitempty"`
	Operation     OperationType          `json:"operation"`
	Format        DataFormat             `json:"format"`
	SourceSize    int64                  `json:"source_size"`
	Success       bool                   `json:"success"`
	Error         string                 `json:"error,omitempty"`
	Duration      time.Duration          `json:"duration"`
	Timestamp     time.Time              `json:"timestamp"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	IPAddress     string                 `json:"ip_address,omitempty"`
	UserAgent     string                 `json:"user_agent,omitempty"`
}

// ParseStatistics contains parsing operation statistics
type ParseStatistics struct {
	TotalOperations      int64                        `json:"total_operations"`
	SuccessfulOperations int64                        `json:"successful_operations"`
	FailedOperations     int64                        `json:"failed_operations"`
	AverageDuration      time.Duration                `json:"average_duration"`
	TotalDataProcessed   int64                        `json:"total_data_processed"`
	FormatBreakdown      map[DataFormat]int64         `json:"format_breakdown"`
	OperationBreakdown   map[OperationType]int64      `json:"operation_breakdown"`
	ErrorBreakdown       map[string]int64             `json:"error_breakdown"`
	PeakUsageTime        time.Time                    `json:"peak_usage_time"`
	GeneratedAt          time.Time                    `json:"generated_at"`
}

// Filter entities

// ParseFilter defines filters for querying parsed data
type ParseFilter struct {
	IDs         []string               `json:"ids,omitempty"`
	Formats     []DataFormat           `json:"formats,omitempty"`
	Tags        map[string]string      `json:"tags,omitempty"`
	CreatedAfter *time.Time            `json:"created_after,omitempty"`
	CreatedBefore *time.Time           `json:"created_before,omitempty"`
	MinSize     int64                  `json:"min_size,omitempty"`
	MaxSize     int64                  `json:"max_size,omitempty"`
	HasErrors   *bool                  `json:"has_errors,omitempty"`
	SourceType  SourceType             `json:"source_type,omitempty"`
	Limit       int                    `json:"limit,omitempty"`
	Offset      int                    `json:"offset,omitempty"`
	SortBy      string                 `json:"sort_by,omitempty"`
	SortOrder   SortOrder              `json:"sort_order,omitempty"`
}

// ParseAuditFilter defines filters for querying parse audit records
type ParseAuditFilter struct {
	UserIDs     []string               `json:"user_ids,omitempty"`
	Operations  []OperationType        `json:"operations,omitempty"`
	Formats     []DataFormat           `json:"formats,omitempty"`
	Success     *bool                  `json:"success,omitempty"`
	StartTime   *time.Time             `json:"start_time,omitempty"`
	EndTime     *time.Time             `json:"end_time,omitempty"`
	MinDuration time.Duration          `json:"min_duration,omitempty"`
	MaxDuration time.Duration          `json:"max_duration,omitempty"`
	IPAddresses []string               `json:"ip_addresses,omitempty"`
	Limit       int                    `json:"limit,omitempty"`
	Offset      int                    `json:"offset,omitempty"`
}

// TimeRange defines a time range for queries
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Enum types

// DataFormat represents supported data formats
type DataFormat string

const (
	FormatJSON DataFormat = "json"
	FormatYAML DataFormat = "yaml"
	FormatXML  DataFormat = "xml"
	FormatCSV  DataFormat = "csv"
	FormatTOML DataFormat = "toml"
	FormatINI  DataFormat = "ini"
	FormatTSV  DataFormat = "tsv"
	FormatHTML DataFormat = "html"
	FormatTXT  DataFormat = "txt"
	FormatUnknown DataFormat = "unknown"
)

// DataType represents data types for validation
type DataType string

const (
	TypeString   DataType = "string"
	TypeInteger  DataType = "integer"
	TypeFloat    DataType = "float"
	TypeBoolean  DataType = "boolean"
	TypeDateTime DataType = "datetime"
	TypeDate     DataType = "date"
	TypeTime     DataType = "time"
	TypeEmail    DataType = "email"
	TypeURL      DataType = "url"
	TypeUUID     DataType = "uuid"
	TypeJSON     DataType = "json"
)

// SourceType represents the source type of data
type SourceType string

const (
	SourceFile   SourceType = "file"
	SourceURL    SourceType = "url"
	SourceString SourceType = "string"
	SourceReader SourceType = "reader"
	SourceStream SourceType = "stream"
)

// CompressionType represents compression types
type CompressionType string

const (
	CompressionNone CompressionType = "none"
	CompressionGzip CompressionType = "gzip"
	CompressionZip  CompressionType = "zip"
	CompressionBzip2 CompressionType = "bzip2"
	CompressionLzma CompressionType = "lzma"
)

// Severity represents error/warning severity levels
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// OperationType represents types of parsing operations
type OperationType string

const (
	OperationParse     OperationType = "parse"
	OperationValidate  OperationType = "validate"
	OperationConvert   OperationType = "convert"
	OperationTransform OperationType = "transform"
	OperationFilter    OperationType = "filter"
	OperationMerge     OperationType = "merge"
	OperationExtract   OperationType = "extract"
)

// MergeStrategy represents strategies for merging data
type MergeStrategy string

const (
	MergeAppend    MergeStrategy = "append"
	MergeOverwrite MergeStrategy = "overwrite"
	MergeUnion     MergeStrategy = "union"
	MergeIntersect MergeStrategy = "intersect"
	MergeCustom    MergeStrategy = "custom"
)

// LineEndingType represents line ending types
type LineEndingType string

const (
	LineEndingLF   LineEndingType = "lf"   // Unix/Linux (\n)
	LineEndingCRLF LineEndingType = "crlf" // Windows (\r\n)
	LineEndingCR   LineEndingType = "cr"   // Classic Mac (\r)
)

// SortOrder represents sort order
type SortOrder string

const (
	SortAsc  SortOrder = "asc"
	SortDesc SortOrder = "desc"
)