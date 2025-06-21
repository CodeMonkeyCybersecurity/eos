// Package parse implements the domain service for data parsing operations
package parse

import (
	"context"
	"fmt"
	"io"
	"time"

	"go.uber.org/zap"
)

// Service implements the ParseService interface and coordinates parsing operations
type Service struct {
	jsonParser      JSONParser
	yamlParser      YAMLParser
	xmlParser       XMLParser
	csvParser       CSVParser
	tomlParser      TOMLParser
	iniParser       INIParser
	formatDetector  FormatDetector
	dataValidator   DataValidator
	dataConverter   DataConverter
	repository      ParseRepository
	auditRepository ParseAuditRepository
	logger          *zap.Logger
}

// NewService creates a new parse domain service
func NewService(
	jsonParser JSONParser,
	yamlParser YAMLParser,
	xmlParser XMLParser,
	csvParser CSVParser,
	tomlParser TOMLParser,
	iniParser INIParser,
	formatDetector FormatDetector,
	dataValidator DataValidator,
	dataConverter DataConverter,
	repository ParseRepository,
	auditRepository ParseAuditRepository,
	logger *zap.Logger,
) *Service {
	return &Service{
		jsonParser:      jsonParser,
		yamlParser:      yamlParser,
		xmlParser:       xmlParser,
		csvParser:       csvParser,
		tomlParser:      tomlParser,
		iniParser:       iniParser,
		formatDetector:  formatDetector,
		dataValidator:   dataValidator,
		dataConverter:   dataConverter,
		repository:      repository,
		auditRepository: auditRepository,
		logger:          logger,
	}
}

// JSON operations

// ParseJSON parses JSON string into structured data
func (s *Service) ParseJSON(ctx context.Context, input string) (*ParsedData, error) {
	start := time.Now()

	s.logger.Info("Starting JSON parsing", zap.Int("input_size", len(input)))

	parsedValue, err := s.jsonParser.Parse(ctx, input)
	if err != nil {
		s.recordOperation(ctx, OperationParse, FormatJSON, int64(len(input)), false, err, time.Since(start))
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	result := &ParsedData{
		ID:           s.generateID(),
		OriginalData: input,
		ParsedValue:  parsedValue,
		Format:       FormatJSON,
		Metadata: &ParseMetadata{
			Size:          int64(len(input)),
			ParseDuration: time.Since(start),
			Parser:        "json",
			Encoding:      "utf-8",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Source: &DataSource{
			Type:        SourceString,
			Size:        int64(len(input)),
			ContentType: "application/json",
		},
	}

	s.recordOperation(ctx, OperationParse, FormatJSON, int64(len(input)), true, nil, time.Since(start))
	s.logger.Info("JSON parsing completed successfully", zap.Duration("duration", time.Since(start)))

	return result, nil
}

// ParseJSONFromReader parses JSON from an io.Reader
func (s *Service) ParseJSONFromReader(ctx context.Context, reader io.Reader) (*ParsedData, error) {
	// Read all data from reader first
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read from reader: %w", err)
	}

	return s.ParseJSON(ctx, string(data))
}

// FormatJSON formats data as JSON string
func (s *Service) FormatJSON(ctx context.Context, data interface{}, pretty bool) (string, error) {
	start := time.Now()

	result, err := s.jsonParser.Format(ctx, data, pretty)
	if err != nil {
		return "", fmt.Errorf("failed to format JSON: %w", err)
	}

	s.logger.Info("JSON formatting completed", zap.Bool("pretty", pretty), zap.Duration("duration", time.Since(start)))
	return result, nil
}

// YAML operations

// ParseYAML parses YAML string into structured data
func (s *Service) ParseYAML(ctx context.Context, input string) (*ParsedData, error) {
	start := time.Now()

	s.logger.Info("Starting YAML parsing", zap.Int("input_size", len(input)))

	parsedValue, err := s.yamlParser.Parse(ctx, input)
	if err != nil {
		s.recordOperation(ctx, OperationParse, FormatYAML, int64(len(input)), false, err, time.Since(start))
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	result := &ParsedData{
		ID:           s.generateID(),
		OriginalData: input,
		ParsedValue:  parsedValue,
		Format:       FormatYAML,
		Metadata: &ParseMetadata{
			Size:          int64(len(input)),
			ParseDuration: time.Since(start),
			Parser:        "yaml",
			Encoding:      "utf-8",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Source: &DataSource{
			Type:        SourceString,
			Size:        int64(len(input)),
			ContentType: "application/yaml",
		},
	}

	s.recordOperation(ctx, OperationParse, FormatYAML, int64(len(input)), true, nil, time.Since(start))
	s.logger.Info("YAML parsing completed successfully", zap.Duration("duration", time.Since(start)))

	return result, nil
}

// ParseYAMLFromReader parses YAML from an io.Reader
func (s *Service) ParseYAMLFromReader(ctx context.Context, reader io.Reader) (*ParsedData, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read from reader: %w", err)
	}

	return s.ParseYAML(ctx, string(data))
}

// FormatYAML formats data as YAML string
func (s *Service) FormatYAML(ctx context.Context, data interface{}) (string, error) {
	start := time.Now()

	result, err := s.yamlParser.Format(ctx, data)
	if err != nil {
		return "", fmt.Errorf("failed to format YAML: %w", err)
	}

	s.logger.Info("YAML formatting completed", zap.Duration("duration", time.Since(start)))
	return result, nil
}

// XML operations

// ParseXML parses XML string into structured data
func (s *Service) ParseXML(ctx context.Context, input string) (*ParsedData, error) {
	start := time.Now()

	s.logger.Info("Starting XML parsing", zap.Int("input_size", len(input)))

	parsedValue, err := s.xmlParser.Parse(ctx, input)
	if err != nil {
		s.recordOperation(ctx, OperationParse, FormatXML, int64(len(input)), false, err, time.Since(start))
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	result := &ParsedData{
		ID:           s.generateID(),
		OriginalData: input,
		ParsedValue:  parsedValue,
		Format:       FormatXML,
		Metadata: &ParseMetadata{
			Size:          int64(len(input)),
			ParseDuration: time.Since(start),
			Parser:        "xml",
			Encoding:      "utf-8",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Source: &DataSource{
			Type:        SourceString,
			Size:        int64(len(input)),
			ContentType: "application/xml",
		},
	}

	s.recordOperation(ctx, OperationParse, FormatXML, int64(len(input)), true, nil, time.Since(start))
	s.logger.Info("XML parsing completed successfully", zap.Duration("duration", time.Since(start)))

	return result, nil
}

// ParseXMLFromReader parses XML from an io.Reader
func (s *Service) ParseXMLFromReader(ctx context.Context, reader io.Reader) (*ParsedData, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read from reader: %w", err)
	}

	return s.ParseXML(ctx, string(data))
}

// FormatXML formats data as XML string
func (s *Service) FormatXML(ctx context.Context, data interface{}, pretty bool) (string, error) {
	start := time.Now()

	result, err := s.xmlParser.Format(ctx, data, pretty)
	if err != nil {
		return "", fmt.Errorf("failed to format XML: %w", err)
	}

	s.logger.Info("XML formatting completed", zap.Bool("pretty", pretty), zap.Duration("duration", time.Since(start)))
	return result, nil
}

// CSV operations

// ParseCSV parses CSV string into structured data
func (s *Service) ParseCSV(ctx context.Context, input string, config *CSVConfig) (*ParsedData, error) {
	start := time.Now()

	s.logger.Info("Starting CSV parsing", zap.Int("input_size", len(input)))

	if config == nil {
		config = &CSVConfig{
			Delimiter: ',',
			Quote:     '"',
			HasHeader: true,
			TrimSpace: true,
		}
	}

	parsedValue, err := s.csvParser.Parse(ctx, input, config)
	if err != nil {
		s.recordOperation(ctx, OperationParse, FormatCSV, int64(len(input)), false, err, time.Since(start))
		return nil, fmt.Errorf("failed to parse CSV: %w", err)
	}

	result := &ParsedData{
		ID:           s.generateID(),
		OriginalData: input,
		ParsedValue:  parsedValue,
		Format:       FormatCSV,
		Metadata: &ParseMetadata{
			Size:          int64(len(input)),
			RecordCount:   len(parsedValue),
			ParseDuration: time.Since(start),
			Parser:        "csv",
			Encoding:      "utf-8",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Source: &DataSource{
			Type:        SourceString,
			Size:        int64(len(input)),
			ContentType: "text/csv",
		},
	}

	s.recordOperation(ctx, OperationParse, FormatCSV, int64(len(input)), true, nil, time.Since(start))
	s.logger.Info("CSV parsing completed successfully", zap.Duration("duration", time.Since(start)), zap.Int("records", len(parsedValue)))

	return result, nil
}

// ParseCSVFromReader parses CSV from an io.Reader
func (s *Service) ParseCSVFromReader(ctx context.Context, reader io.Reader, config *CSVConfig) (*ParsedData, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read from reader: %w", err)
	}

	return s.ParseCSV(ctx, string(data), config)
}

// FormatCSV formats data as CSV string
func (s *Service) FormatCSV(ctx context.Context, data []map[string]interface{}, config *CSVConfig) (string, error) {
	start := time.Now()

	if config == nil {
		config = &CSVConfig{
			Delimiter: ',',
			Quote:     '"',
			HasHeader: true,
		}
	}

	result, err := s.csvParser.Format(ctx, data, config)
	if err != nil {
		return "", fmt.Errorf("failed to format CSV: %w", err)
	}

	s.logger.Info("CSV formatting completed", zap.Duration("duration", time.Since(start)), zap.Int("records", len(data)))
	return result, nil
}

// TOML operations

// ParseTOML parses TOML string into structured data
func (s *Service) ParseTOML(ctx context.Context, input string) (*ParsedData, error) {
	start := time.Now()

	s.logger.Info("Starting TOML parsing", zap.Int("input_size", len(input)))

	parsedValue, err := s.tomlParser.Parse(ctx, input)
	if err != nil {
		s.recordOperation(ctx, OperationParse, FormatTOML, int64(len(input)), false, err, time.Since(start))
		return nil, fmt.Errorf("failed to parse TOML: %w", err)
	}

	result := &ParsedData{
		ID:           s.generateID(),
		OriginalData: input,
		ParsedValue:  parsedValue,
		Format:       FormatTOML,
		Metadata: &ParseMetadata{
			Size:          int64(len(input)),
			ParseDuration: time.Since(start),
			Parser:        "toml",
			Encoding:      "utf-8",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Source: &DataSource{
			Type:        SourceString,
			Size:        int64(len(input)),
			ContentType: "application/toml",
		},
	}

	s.recordOperation(ctx, OperationParse, FormatTOML, int64(len(input)), true, nil, time.Since(start))
	s.logger.Info("TOML parsing completed successfully", zap.Duration("duration", time.Since(start)))

	return result, nil
}

// FormatTOML formats data as TOML string
func (s *Service) FormatTOML(ctx context.Context, data interface{}) (string, error) {
	start := time.Now()

	result, err := s.tomlParser.Format(ctx, data)
	if err != nil {
		return "", fmt.Errorf("failed to format TOML: %w", err)
	}

	s.logger.Info("TOML formatting completed", zap.Duration("duration", time.Since(start)))
	return result, nil
}

// INI operations

// ParseINI parses INI string into structured data
func (s *Service) ParseINI(ctx context.Context, input string) (*ParsedData, error) {
	start := time.Now()

	s.logger.Info("Starting INI parsing", zap.Int("input_size", len(input)))

	parsedValue, err := s.iniParser.Parse(ctx, input)
	if err != nil {
		s.recordOperation(ctx, OperationParse, FormatINI, int64(len(input)), false, err, time.Since(start))
		return nil, fmt.Errorf("failed to parse INI: %w", err)
	}

	result := &ParsedData{
		ID:           s.generateID(),
		OriginalData: input,
		ParsedValue:  parsedValue,
		Format:       FormatINI,
		Metadata: &ParseMetadata{
			Size:          int64(len(input)),
			ParseDuration: time.Since(start),
			Parser:        "ini",
			Encoding:      "utf-8",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Source: &DataSource{
			Type:        SourceString,
			Size:        int64(len(input)),
			ContentType: "text/plain",
		},
	}

	s.recordOperation(ctx, OperationParse, FormatINI, int64(len(input)), true, nil, time.Since(start))
	s.logger.Info("INI parsing completed successfully", zap.Duration("duration", time.Since(start)))

	return result, nil
}

// FormatINI formats data as INI string
func (s *Service) FormatINI(ctx context.Context, data map[string]map[string]string) (string, error) {
	start := time.Now()

	result, err := s.iniParser.Format(ctx, data)
	if err != nil {
		return "", fmt.Errorf("failed to format INI: %w", err)
	}

	s.logger.Info("INI formatting completed", zap.Duration("duration", time.Since(start)))
	return result, nil
}

// Generic operations

// DetectFormat detects the format of input data
func (s *Service) DetectFormat(ctx context.Context, input string) (DataFormat, float64, error) {
	return s.formatDetector.DetectFormat(ctx, input)
}

// Convert converts data between formats
func (s *Service) Convert(ctx context.Context, input string, fromFormat, toFormat DataFormat, options *ConvertOptions) (string, error) {
	start := time.Now()

	s.logger.Info("Starting format conversion",
		zap.String("from", string(fromFormat)),
		zap.String("to", string(toFormat)),
		zap.Int("input_size", len(input)))

	result, err := s.dataConverter.Convert(ctx, input, fromFormat, toFormat, options)
	if err != nil {
		s.recordOperation(ctx, OperationConvert, fromFormat, int64(len(input)), false, err, time.Since(start))
		return "", fmt.Errorf("failed to convert from %s to %s: %w", fromFormat, toFormat, err)
	}

	s.recordOperation(ctx, OperationConvert, fromFormat, int64(len(input)), true, nil, time.Since(start))
	s.logger.Info("Format conversion completed successfully",
		zap.Duration("duration", time.Since(start)),
		zap.Int("output_size", len(result)))

	return result, nil
}

// Validate validates parsed data against a schema
func (s *Service) Validate(ctx context.Context, input string, format DataFormat, schema interface{}) (*ValidationResult, error) {
	start := time.Now()

	s.logger.Info("Starting data validation", zap.String("format", string(format)))

	var result *ValidationResult
	var err error

	switch format {
	case FormatJSON:
		// Parse first to get structured data
		parsedData, parseErr := s.jsonParser.Parse(ctx, input)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse JSON for validation: %w", parseErr)
		}
		result, err = s.dataValidator.ValidateJSON(ctx, parsedData, schema)
	case FormatYAML:
		parsedData, parseErr := s.yamlParser.Parse(ctx, input)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse YAML for validation: %w", parseErr)
		}
		result, err = s.dataValidator.ValidateYAML(ctx, parsedData, schema)
	case FormatXML:
		parsedData, parseErr := s.xmlParser.Parse(ctx, input)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse XML for validation: %w", parseErr)
		}
		result, err = s.dataValidator.ValidateXML(ctx, parsedData, schema)
	default:
		return nil, fmt.Errorf("validation not supported for format: %s", format)
	}

	if err != nil {
		s.recordOperation(ctx, OperationValidate, format, int64(len(input)), false, err, time.Since(start))
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	s.recordOperation(ctx, OperationValidate, format, int64(len(input)), true, nil, time.Since(start))
	s.logger.Info("Data validation completed",
		zap.Duration("duration", time.Since(start)),
		zap.Bool("valid", result.Valid))

	return result, nil
}

// Transformation operations

// Transform applies a transformation to parsed data
func (s *Service) Transform(ctx context.Context, data *ParsedData, transformer DataTransformer) (*ParsedData, error) {
	start := time.Now()

	s.logger.Info("Starting data transformation", zap.String("transformer", transformer.GetName()))

	result, err := transformer.Transform(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("transformation failed: %w", err)
	}

	result.UpdatedAt = time.Now()
	if result.Metadata != nil {
		result.Metadata.ParseDuration += time.Since(start)
	}

	s.logger.Info("Data transformation completed",
		zap.Duration("duration", time.Since(start)),
		zap.String("transformer", transformer.GetName()))

	return result, nil
}

// ExtractFields extracts specific fields from parsed data
func (s *Service) ExtractFields(ctx context.Context, data *ParsedData, fields []string) (*ParsedData, error) {
	s.logger.Info("Extracting fields from data", zap.Strings("fields", fields))

	// Implementation would depend on the specific data format and structure
	// This is a simplified version that works with map[string]interface{}
	if dataMap, ok := data.ParsedValue.(map[string]interface{}); ok {
		extracted := make(map[string]interface{})
		for _, field := range fields {
			if value, exists := dataMap[field]; exists {
				extracted[field] = value
			}
		}

		result := *data // Copy the structure
		result.ParsedValue = extracted
		result.UpdatedAt = time.Now()

		return &result, nil
	}

	return nil, fmt.Errorf("field extraction not supported for data type: %T", data.ParsedValue)
}

// FilterData filters parsed data based on criteria
func (s *Service) FilterData(ctx context.Context, data *ParsedData, filter DataFilter) (*ParsedData, error) {
	start := time.Now()

	s.logger.Info("Filtering data", zap.String("criteria", filter.GetCriteria()))

	result, err := filter.Filter(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("data filtering failed: %w", err)
	}

	result.UpdatedAt = time.Now()
	if result.Metadata != nil {
		result.Metadata.ParseDuration += time.Since(start)
	}

	s.logger.Info("Data filtering completed", zap.Duration("duration", time.Since(start)))

	return result, nil
}

// Batch operations

// ParseMultiple parses multiple inputs of the same format
func (s *Service) ParseMultiple(ctx context.Context, inputs []string, format DataFormat) ([]*ParsedData, error) {
	s.logger.Info("Starting batch parsing", zap.Int("count", len(inputs)), zap.String("format", string(format)))

	results := make([]*ParsedData, len(inputs))
	for i, input := range inputs {
		var result *ParsedData
		var err error

		switch format {
		case FormatJSON:
			result, err = s.ParseJSON(ctx, input)
		case FormatYAML:
			result, err = s.ParseYAML(ctx, input)
		case FormatXML:
			result, err = s.ParseXML(ctx, input)
		case FormatCSV:
			result, err = s.ParseCSV(ctx, input, nil)
		case FormatTOML:
			result, err = s.ParseTOML(ctx, input)
		case FormatINI:
			result, err = s.ParseINI(ctx, input)
		default:
			return nil, fmt.Errorf("batch parsing not supported for format: %s", format)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to parse input %d: %w", i, err)
		}

		results[i] = result
	}

	s.logger.Info("Batch parsing completed", zap.Int("count", len(results)))
	return results, nil
}

// MergeData merges multiple datasets using the specified strategy
func (s *Service) MergeData(ctx context.Context, datasets []*ParsedData, strategy MergeStrategy) (*ParsedData, error) {
	start := time.Now()

	s.logger.Info("Starting data merge", zap.Int("datasets", len(datasets)), zap.String("strategy", string(strategy)))

	if len(datasets) == 0 {
		return nil, fmt.Errorf("no datasets to merge")
	}

	if len(datasets) == 1 {
		return datasets[0], nil
	}

	// Implementation would depend on the merge strategy and data types
	// This is a simplified implementation for demonstration
	merged := &ParsedData{
		ID:        s.generateID(),
		Format:    datasets[0].Format,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata: &ParseMetadata{
			ParseDuration: time.Since(start),
			Parser:        "merger",
		},
	}

	switch strategy {
	case MergeAppend:
		// Append all data together (for arrays/slices)
		var mergedValue []interface{}
		for _, dataset := range datasets {
			if slice, ok := dataset.ParsedValue.([]interface{}); ok {
				mergedValue = append(mergedValue, slice...)
			} else {
				mergedValue = append(mergedValue, dataset.ParsedValue)
			}
		}
		merged.ParsedValue = mergedValue
	case MergeOverwrite:
		// Last dataset wins
		merged.ParsedValue = datasets[len(datasets)-1].ParsedValue
	default:
		return nil, fmt.Errorf("merge strategy not implemented: %s", strategy)
	}

	s.logger.Info("Data merge completed", zap.Duration("duration", time.Since(start)))
	return merged, nil
}

// Helper methods

// generateID generates a unique ID for parsed data
func (s *Service) generateID() string {
	return fmt.Sprintf("parse_%d", time.Now().UnixNano())
}

// recordOperation records a parsing operation for audit purposes
func (s *Service) recordOperation(ctx context.Context, operation OperationType, format DataFormat, size int64, success bool, err error, duration time.Duration) {
	if s.auditRepository == nil {
		return
	}

	auditErr := ""
	if err != nil {
		auditErr = err.Error()
	}

	op := &ParseOperation{
		ID:         fmt.Sprintf("op_%d", time.Now().UnixNano()),
		Operation:  operation,
		Format:     format,
		SourceSize: size,
		Success:    success,
		Error:      auditErr,
		Duration:   duration,
		Timestamp:  time.Now(),
	}

	if auditRecordErr := s.auditRepository.RecordParseOperation(ctx, op); auditRecordErr != nil {
		s.logger.Warn("Failed to record parse operation", zap.Error(auditRecordErr))
	}
}
