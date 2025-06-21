// Package stringutils defines domain entities for string manipulation and validation
package stringutils

import (
	"regexp"
	"time"
)

// Core string operation entities

// StringData represents a string with associated metadata
type StringData struct {
	ID         string            `json:"id"`
	Content    string            `json:"content"`
	Encoding   StringEncoding    `json:"encoding"`
	Length     int               `json:"length"`
	Hash       string            `json:"hash,omitempty"`
	Metadata   *StringMetadata   `json:"metadata,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	Source     *StringSource     `json:"source,omitempty"`
	Validation *ValidationResult `json:"validation,omitempty"`
}

// StringMetadata contains metadata about string content
type StringMetadata struct {
	ByteSize       int64             `json:"byte_size"`
	RuneCount      int               `json:"rune_count"`
	LineCount      int               `json:"line_count"`
	WordCount      int               `json:"word_count"`
	CharacterCount int               `json:"character_count"`
	Language       string            `json:"language,omitempty"`
	ContentType    string            `json:"content_type,omitempty"`
	Checksum       string            `json:"checksum,omitempty"`
	Compression    CompressionType   `json:"compression,omitempty"`
	CustomFields   map[string]string `json:"custom_fields,omitempty"`
}

// StringSource represents the source of string data
type StringSource struct {
	Type         SourceType     `json:"type"`
	Location     string         `json:"location"`
	Filename     string         `json:"filename,omitempty"`
	URL          string         `json:"url,omitempty"`
	Encoding     StringEncoding `json:"encoding"`
	Size         int64          `json:"size,omitempty"`
	LastModified *time.Time     `json:"last_modified,omitempty"`
}

// StringDestination represents the destination for string data
type StringDestination struct {
	Type     DestinationType `json:"type"`
	Location string          `json:"location"`
	Filename string          `json:"filename,omitempty"`
	Encoding StringEncoding  `json:"encoding"`
	Append   bool            `json:"append"`
}

// Configuration entities

// TrimOptions defines options for string trimming
type TrimOptions struct {
	TrimType       TrimType `json:"trim_type"`
	Characters     string   `json:"characters,omitempty"`
	RemoveEmpty    bool     `json:"remove_empty"`
	NormalizeSpace bool     `json:"normalize_space"`
}

// SplitConfig defines configuration for string splitting
type SplitConfig struct {
	Separator     string    `json:"separator"`
	MaxSplit      int       `json:"max_split,omitempty"`
	TrimResults   bool      `json:"trim_results"`
	RemoveEmpty   bool      `json:"remove_empty"`
	SplitType     SplitType `json:"split_type"`
	CaseSensitive bool      `json:"case_sensitive"`
}

// ReplaceConfig defines configuration for string replacement
type ReplaceConfig struct {
	SearchText    string `json:"search_text"`
	ReplaceText   string `json:"replace_text"`
	ReplaceAll    bool   `json:"replace_all"`
	CaseSensitive bool   `json:"case_sensitive"`
	UseRegex      bool   `json:"use_regex"`
	MaxReplace    int    `json:"max_replace,omitempty"`
}

// ValidationRules defines rules for string validation
type ValidationRules struct {
	MinLength        int                    `json:"min_length,omitempty"`
	MaxLength        int                    `json:"max_length,omitempty"`
	Pattern          string                 `json:"pattern,omitempty"`
	Format           StringFormat           `json:"format,omitempty"`
	AllowedChars     string                 `json:"allowed_chars,omitempty"`
	ForbiddenChars   string                 `json:"forbidden_chars,omitempty"`
	Blacklist        []string               `json:"blacklist,omitempty"`
	Whitelist        []string               `json:"whitelist,omitempty"`
	RequireNumeric   bool                   `json:"require_numeric"`
	RequireAlpha     bool                   `json:"require_alpha"`
	RequireSpecial   bool                   `json:"require_special"`
	CaseSensitive    bool                   `json:"case_sensitive"`
	CustomValidators map[string]interface{} `json:"custom_validators,omitempty"`
}

// ValidationResult represents the result of string validation
type ValidationResult struct {
	Valid        bool                 `json:"valid"`
	Errors       []*ValidationError   `json:"errors,omitempty"`
	Warnings     []*ValidationWarning `json:"warnings,omitempty"`
	Score        float64              `json:"score"`
	Details      *ValidationDetails   `json:"details,omitempty"`
	ValidatedAt  time.Time            `json:"validated_at"`
	Validator    string               `json:"validator"`
	RulesApplied []string             `json:"rules_applied"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Code     string      `json:"code"`
	Message  string      `json:"message"`
	Field    string      `json:"field,omitempty"`
	Value    interface{} `json:"value,omitempty"`
	Expected interface{} `json:"expected,omitempty"`
	Position int         `json:"position,omitempty"`
	Severity Severity    `json:"severity"`
	Rule     string      `json:"rule"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Code       string      `json:"code"`
	Message    string      `json:"message"`
	Value      interface{} `json:"value,omitempty"`
	Suggestion string      `json:"suggestion,omitempty"`
	Position   int         `json:"position,omitempty"`
	Rule       string      `json:"rule"`
}

// ValidationDetails contains detailed validation information
type ValidationDetails struct {
	Length           int                    `json:"length"`
	ByteSize         int64                  `json:"byte_size"`
	RuneCount        int                    `json:"rune_count"`
	CharacterTypes   map[string]int         `json:"character_types"`
	DetectedFormat   StringFormat           `json:"detected_format,omitempty"`
	DetectedEncoding StringEncoding         `json:"detected_encoding,omitempty"`
	SecurityIssues   []*SecurityIssue       `json:"security_issues,omitempty"`
	QualityMetrics   map[string]interface{} `json:"quality_metrics,omitempty"`
}

// SecurityIssue represents a security issue found in string content
type SecurityIssue struct {
	Type        SecurityIssueType `json:"type"`
	Severity    Severity          `json:"severity"`
	Description string            `json:"description"`
	Position    int               `json:"position,omitempty"`
	Context     string            `json:"context,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
}

// SanitizeOptions defines options for string sanitization
type SanitizeOptions struct {
	RemoveControlChars   bool              `json:"remove_control_chars"`
	RemoveNonPrintable   bool              `json:"remove_non_printable"`
	RemoveEmojis         bool              `json:"remove_emojis"`
	RemoveHTML           bool              `json:"remove_html"`
	RemoveSQL            bool              `json:"remove_sql"`
	RemoveJavaScript     bool              `json:"remove_javascript"`
	NormalizeWhitespace  bool              `json:"normalize_whitespace"`
	NormalizeLineEndings bool              `json:"normalize_line_endings"`
	LineEndingType       LineEndingType    `json:"line_ending_type,omitempty"`
	CustomFilters        map[string]string `json:"custom_filters,omitempty"`
	PreserveTags         []string          `json:"preserve_tags,omitempty"`
}

// PathValidationOptions defines options for path validation
type PathValidationOptions struct {
	AllowRelative    bool     `json:"allow_relative"`
	AllowAbsolute    bool     `json:"allow_absolute"`
	AllowTraversal   bool     `json:"allow_traversal"`
	RequireExists    bool     `json:"require_exists"`
	AllowedRoots     []string `json:"allowed_roots,omitempty"`
	ForbiddenPaths   []string `json:"forbidden_paths,omitempty"`
	MaxDepth         int      `json:"max_depth,omitempty"`
	CheckPermissions bool     `json:"check_permissions"`
}

// String analysis entities

// StringAnalysis contains comprehensive string analysis results
type StringAnalysis struct {
	Content     *ContentAnalysis     `json:"content"`
	Complexity  *ComplexityAnalysis  `json:"complexity"`
	Language    *LanguageAnalysis    `json:"language,omitempty"`
	Sentiment   *SentimentAnalysis   `json:"sentiment,omitempty"`
	Security    *SecurityAnalysis    `json:"security"`
	Quality     *QualityAnalysis     `json:"quality"`
	Performance *PerformanceAnalysis `json:"performance"`
	GeneratedAt time.Time            `json:"generated_at"`
}

// ContentAnalysis contains content-specific analysis
type ContentAnalysis struct {
	Length          int                    `json:"length"`
	ByteSize        int64                  `json:"byte_size"`
	RuneCount       int                    `json:"rune_count"`
	LineCount       int                    `json:"line_count"`
	WordCount       int                    `json:"word_count"`
	SentenceCount   int                    `json:"sentence_count"`
	ParagraphCount  int                    `json:"paragraph_count"`
	CharFrequency   map[rune]int           `json:"char_frequency"`
	WordFrequency   map[string]int         `json:"word_frequency"`
	Encoding        StringEncoding         `json:"encoding"`
	ContentType     string                 `json:"content_type"`
	HasSpecialChars bool                   `json:"has_special_chars"`
	HasNumbers      bool                   `json:"has_numbers"`
	HasSymbols      bool                   `json:"has_symbols"`
	Statistics      map[string]interface{} `json:"statistics"`
}

// ComplexityAnalysis contains complexity metrics
type ComplexityAnalysis struct {
	Score                 float64            `json:"score"`
	Level                 ComplexityLevel    `json:"level"`
	Readability           float64            `json:"readability"`
	VocabularySize        int                `json:"vocabulary_size"`
	AverageWordLength     float64            `json:"average_word_length"`
	AverageSentenceLength float64            `json:"average_sentence_length"`
	SyllableCount         int                `json:"syllable_count"`
	ComplexWords          int                `json:"complex_words"`
	Metrics               map[string]float64 `json:"metrics"`
}

// LanguageAnalysis contains language detection results
type LanguageAnalysis struct {
	DetectedLanguage string           `json:"detected_language"`
	Confidence       float64          `json:"confidence"`
	Alternatives     []LanguageOption `json:"alternatives,omitempty"`
	Script           string           `json:"script,omitempty"`
	Region           string           `json:"region,omitempty"`
	Encoding         StringEncoding   `json:"encoding"`
	TextDirection    TextDirection    `json:"text_direction"`
}

// LanguageOption represents a language detection option
type LanguageOption struct {
	Language   string  `json:"language"`
	Confidence float64 `json:"confidence"`
	Script     string  `json:"script,omitempty"`
}

// SentimentAnalysis contains sentiment analysis results
type SentimentAnalysis struct {
	OverallSentiment Sentiment          `json:"overall_sentiment"`
	Score            float64            `json:"score"`
	Confidence       float64            `json:"confidence"`
	Emotions         map[string]float64 `json:"emotions,omitempty"`
	Keywords         []string           `json:"keywords,omitempty"`
	Phrases          []SentimentPhrase  `json:"phrases,omitempty"`
}

// SentimentPhrase represents a phrase with sentiment
type SentimentPhrase struct {
	Text      string    `json:"text"`
	Sentiment Sentiment `json:"sentiment"`
	Score     float64   `json:"score"`
	Position  int       `json:"position"`
}

// SecurityAnalysis contains security analysis results
type SecurityAnalysis struct {
	ThreatLevel    ThreatLevel      `json:"threat_level"`
	Issues         []*SecurityIssue `json:"issues,omitempty"`
	Score          float64          `json:"score"`
	HasSQL         bool             `json:"has_sql"`
	HasHTML        bool             `json:"has_html"`
	HasJavaScript  bool             `json:"has_javascript"`
	HasShellMeta   bool             `json:"has_shell_meta"`
	HasSecrets     bool             `json:"has_secrets"`
	SecretPatterns []string         `json:"secret_patterns,omitempty"`
}

// QualityAnalysis contains quality metrics
type QualityAnalysis struct {
	Score        float64            `json:"score"`
	Grade        QualityGrade       `json:"grade"`
	Issues       []string           `json:"issues,omitempty"`
	Suggestions  []string           `json:"suggestions,omitempty"`
	Consistency  float64            `json:"consistency"`
	Completeness float64            `json:"completeness"`
	Accuracy     float64            `json:"accuracy"`
	Metrics      map[string]float64 `json:"metrics"`
}

// PerformanceAnalysis contains performance metrics
type PerformanceAnalysis struct {
	ProcessingTime    time.Duration      `json:"processing_time"`
	MemoryUsage       int64              `json:"memory_usage"`
	CompressionRatio  float64            `json:"compression_ratio"`
	IndexingTime      time.Duration      `json:"indexing_time"`
	SearchPerformance map[string]float64 `json:"search_performance"`
}

// Comparison and similarity entities

// CompareOptions defines options for string comparison
type CompareOptions struct {
	CaseSensitive    bool             `json:"case_sensitive"`
	IgnoreWhitespace bool             `json:"ignore_whitespace"`
	Algorithm        CompareAlgorithm `json:"algorithm"`
	Threshold        float64          `json:"threshold,omitempty"`
	ShowDifferences  bool             `json:"show_differences"`
	ContextLines     int              `json:"context_lines,omitempty"`
}

// CompareResult represents the result of string comparison
type CompareResult struct {
	Similar          bool                   `json:"similar"`
	Similarity       float64                `json:"similarity"`
	Distance         int                    `json:"distance"`
	Algorithm        CompareAlgorithm       `json:"algorithm"`
	Differences      []*StringDiff          `json:"differences,omitempty"`
	CommonSubstrings []string               `json:"common_substrings,omitempty"`
	Statistics       map[string]interface{} `json:"statistics"`
	ComparedAt       time.Time              `json:"compared_at"`
}

// StringDiff represents a difference between two strings
type StringDiff struct {
	Type     DiffType `json:"type"`
	Position int      `json:"position"`
	Length   int      `json:"length"`
	Original string   `json:"original,omitempty"`
	Modified string   `json:"modified,omitempty"`
	Context  string   `json:"context,omitempty"`
}

// SimilarityResult represents similarity between strings
type SimilarityResult struct {
	Text       string  `json:"text"`
	Similarity float64 `json:"similarity"`
	Distance   int     `json:"distance"`
	Algorithm  string  `json:"algorithm"`
	Rank       int     `json:"rank"`
}

// Generation entities

// RandomStringConfig defines configuration for random string generation
type RandomStringConfig struct {
	Length       int          `json:"length"`
	CharacterSet CharacterSet `json:"character_set"`
	CustomChars  string       `json:"custom_chars,omitempty"`
	ExcludeChars string       `json:"exclude_chars,omitempty"`
	Pattern      string       `json:"pattern,omitempty"`
	NoAmbiguous  bool         `json:"no_ambiguous"`
	Entropy      int          `json:"entropy,omitempty"`
	Seed         int64        `json:"seed,omitempty"`
}

// PasswordConfig defines configuration for password generation
type PasswordConfig struct {
	Length           int    `json:"length"`
	IncludeUpper     bool   `json:"include_upper"`
	IncludeLower     bool   `json:"include_lower"`
	IncludeNumbers   bool   `json:"include_numbers"`
	IncludeSymbols   bool   `json:"include_symbols"`
	ExcludeAmbiguous bool   `json:"exclude_ambiguous"`
	RequiredChars    string `json:"required_chars,omitempty"`
	ForbiddenChars   string `json:"forbidden_chars,omitempty"`
	MinStrength      int    `json:"min_strength"`
}

// SlugOptions defines options for slug generation
type SlugOptions struct {
	Separator     string `json:"separator"`
	MaxLength     int    `json:"max_length,omitempty"`
	Lowercase     bool   `json:"lowercase"`
	RemoveAccents bool   `json:"remove_accents"`
	AllowedChars  string `json:"allowed_chars,omitempty"`
}

// HumanReadableConfig defines configuration for human-readable string generation
type HumanReadableConfig struct {
	WordCount  int      `json:"word_count"`
	Separator  string   `json:"separator"`
	Capitalize bool     `json:"capitalize"`
	Dictionary []string `json:"dictionary,omitempty"`
	AddNumbers bool     `json:"add_numbers"`
	AddSymbols bool     `json:"add_symbols"`
}

// Pattern matching entities

// CompiledPattern represents a compiled pattern for matching
type CompiledPattern struct {
	Pattern    string         `json:"pattern"`
	Regex      *regexp.Regexp `json:"-"`
	Flags      PatternFlags   `json:"flags"`
	CompiledAt time.Time      `json:"compiled_at"`
	Statistics *PatternStats  `json:"statistics,omitempty"`
}

// PatternFlags defines flags for pattern compilation
type PatternFlags struct {
	CaseInsensitive bool `json:"case_insensitive"`
	Multiline       bool `json:"multiline"`
	DotAll          bool `json:"dot_all"`
	Unicode         bool `json:"unicode"`
	Global          bool `json:"global"`
}

// MatchResult represents the result of pattern matching
type MatchResult struct {
	Matched     bool              `json:"matched"`
	Match       string            `json:"match,omitempty"`
	Position    int               `json:"position"`
	Length      int               `json:"length"`
	Groups      []string          `json:"groups,omitempty"`
	NamedGroups map[string]string `json:"named_groups,omitempty"`
}

// PatternValidation represents pattern validation result
type PatternValidation struct {
	Valid       bool     `json:"valid"`
	Error       string   `json:"error,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	Complexity  int      `json:"complexity"`
	Performance string   `json:"performance"`
}

// PatternStats contains pattern usage statistics
type PatternStats struct {
	UsageCount  int           `json:"usage_count"`
	MatchCount  int           `json:"match_count"`
	AverageTime time.Duration `json:"average_time"`
	LastUsed    time.Time     `json:"last_used"`
	ErrorCount  int           `json:"error_count"`
}

// Formatting entities

// NumberFormatOptions defines options for number formatting
type NumberFormatOptions struct {
	DecimalPlaces    int    `json:"decimal_places"`
	ThousandsSep     string `json:"thousands_sep"`
	DecimalSep       string `json:"decimal_sep"`
	Prefix           string `json:"prefix,omitempty"`
	Suffix           string `json:"suffix,omitempty"`
	PadZeros         bool   `json:"pad_zeros"`
	ShowPositiveSign bool   `json:"show_positive_sign"`
}

// TransformOperation represents a transformation operation
type TransformOperation struct {
	Type       TransformType          `json:"type"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Order      int                    `json:"order"`
	Condition  string                 `json:"condition,omitempty"`
}

// TransformRules defines rules for string transformation
type TransformRules struct {
	Operations []TransformOperation `json:"operations"`
	FailFast   bool                 `json:"fail_fast"`
	Validate   bool                 `json:"validate"`
	Metadata   map[string]string    `json:"metadata,omitempty"`
}

// Operation tracking entities

// StringOperation represents a string operation for audit purposes
type StringOperation struct {
	ID            string                 `json:"id"`
	UserID        string                 `json:"user_id,omitempty"`
	Operation     OperationType          `json:"operation"`
	InputSize     int64                  `json:"input_size"`
	OutputSize    int64                  `json:"output_size"`
	Success       bool                   `json:"success"`
	Error         string                 `json:"error,omitempty"`
	Duration      time.Duration          `json:"duration"`
	Timestamp     time.Time              `json:"timestamp"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	IPAddress     string                 `json:"ip_address,omitempty"`
	UserAgent     string                 `json:"user_agent,omitempty"`
	SecurityFlags []string               `json:"security_flags,omitempty"`
}

// OperationStatistics contains operation statistics
type OperationStatistics struct {
	TotalOperations      int64                   `json:"total_operations"`
	SuccessfulOperations int64                   `json:"successful_operations"`
	FailedOperations     int64                   `json:"failed_operations"`
	AverageDuration      time.Duration           `json:"average_duration"`
	TotalDataProcessed   int64                   `json:"total_data_processed"`
	OperationBreakdown   map[OperationType]int64 `json:"operation_breakdown"`
	ErrorBreakdown       map[string]int64        `json:"error_breakdown"`
	SecurityEvents       int64                   `json:"security_events"`
	PeakUsageTime        time.Time               `json:"peak_usage_time"`
	GeneratedAt          time.Time               `json:"generated_at"`
}

// SecurityEvent represents a security-related string operation event
type SecurityEvent struct {
	ID               string            `json:"id"`
	Type             SecurityEventType `json:"type"`
	Severity         Severity          `json:"severity"`
	Description      string            `json:"description"`
	UserID           string            `json:"user_id,omitempty"`
	IPAddress        string            `json:"ip_address,omitempty"`
	Timestamp        time.Time         `json:"timestamp"`
	Context          map[string]string `json:"context,omitempty"`
	Mitigated        bool              `json:"mitigated"`
	MitigationAction string            `json:"mitigation_action,omitempty"`
}

// Filter entities

// StringFilter defines filters for querying string data
type StringFilter struct {
	IDs           []string          `json:"ids,omitempty"`
	ContentSearch string            `json:"content_search,omitempty"`
	MinLength     int               `json:"min_length,omitempty"`
	MaxLength     int               `json:"max_length,omitempty"`
	Encodings     []StringEncoding  `json:"encodings,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
	CreatedAfter  *time.Time        `json:"created_after,omitempty"`
	CreatedBefore *time.Time        `json:"created_before,omitempty"`
	HasValidation *bool             `json:"has_validation,omitempty"`
	IsValid       *bool             `json:"is_valid,omitempty"`
	SourceType    SourceType        `json:"source_type,omitempty"`
	Limit         int               `json:"limit,omitempty"`
	Offset        int               `json:"offset,omitempty"`
	SortBy        string            `json:"sort_by,omitempty"`
	SortOrder     SortOrder         `json:"sort_order,omitempty"`
}

// OperationFilter defines filters for querying operations
type OperationFilter struct {
	UserIDs       []string        `json:"user_ids,omitempty"`
	Operations    []OperationType `json:"operations,omitempty"`
	Success       *bool           `json:"success,omitempty"`
	StartTime     *time.Time      `json:"start_time,omitempty"`
	EndTime       *time.Time      `json:"end_time,omitempty"`
	MinDuration   time.Duration   `json:"min_duration,omitempty"`
	MaxDuration   time.Duration   `json:"max_duration,omitempty"`
	IPAddresses   []string        `json:"ip_addresses,omitempty"`
	SecurityFlags []string        `json:"security_flags,omitempty"`
	Limit         int             `json:"limit,omitempty"`
	Offset        int             `json:"offset,omitempty"`
}

// SecurityEventFilter defines filters for querying security events
type SecurityEventFilter struct {
	Types       []SecurityEventType `json:"types,omitempty"`
	Severities  []Severity          `json:"severities,omitempty"`
	UserIDs     []string            `json:"user_ids,omitempty"`
	IPAddresses []string            `json:"ip_addresses,omitempty"`
	StartTime   *time.Time          `json:"start_time,omitempty"`
	EndTime     *time.Time          `json:"end_time,omitempty"`
	Mitigated   *bool               `json:"mitigated,omitempty"`
	Limit       int                 `json:"limit,omitempty"`
	Offset      int                 `json:"offset,omitempty"`
}

// SearchOptions defines options for string searching
type SearchOptions struct {
	Query            string            `json:"query"`
	CaseSensitive    bool              `json:"case_sensitive"`
	WholeWords       bool              `json:"whole_words"`
	UseRegex         bool              `json:"use_regex"`
	MaxResults       int               `json:"max_results,omitempty"`
	HighlightMatches bool              `json:"highlight_matches"`
	IncludeContext   int               `json:"include_context,omitempty"`
	SortBy           string            `json:"sort_by,omitempty"`
	Filters          map[string]string `json:"filters,omitempty"`
}

// TimeRange defines a time range for queries
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// RuleConfig defines configuration for creating validation rules
type RuleConfig struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Rules       map[string]interface{} `json:"rules"`
	Severity    Severity               `json:"severity"`
	Category    string                 `json:"category"`
	Enabled     bool                   `json:"enabled"`
}

// Enum types

// StringEncoding represents character encodings
type StringEncoding string

const (
	EncodingUTF8        StringEncoding = "utf-8"
	EncodingUTF16       StringEncoding = "utf-16"
	EncodingUTF32       StringEncoding = "utf-32"
	EncodingASCII       StringEncoding = "ascii"
	EncodingLatin1      StringEncoding = "latin-1"
	EncodingWindows1252 StringEncoding = "windows-1252"
	EncodingISO88591    StringEncoding = "iso-8859-1"
)

// StringFormat represents string format types
type StringFormat string

const (
	FormatEmail      StringFormat = "email"
	FormatURL        StringFormat = "url"
	FormatIP         StringFormat = "ip"
	FormatDomain     StringFormat = "domain"
	FormatUUID       StringFormat = "uuid"
	FormatJSON       StringFormat = "json"
	FormatXML        StringFormat = "xml"
	FormatBase64     StringFormat = "base64"
	FormatHex        StringFormat = "hex"
	FormatDateTime   StringFormat = "datetime"
	FormatPhone      StringFormat = "phone"
	FormatCreditCard StringFormat = "credit_card"
	FormatSSN        StringFormat = "ssn"
	FormatCustom     StringFormat = "custom"
)

// SourceType represents the source type of string data
type SourceType string

const (
	SourceFile     SourceType = "file"
	SourceURL      SourceType = "url"
	SourceString   SourceType = "string"
	SourceReader   SourceType = "reader"
	SourceStream   SourceType = "stream"
	SourceDatabase SourceType = "database"
)

// DestinationType represents destination types
type DestinationType string

const (
	DestinationFile     DestinationType = "file"
	DestinationURL      DestinationType = "url"
	DestinationWriter   DestinationType = "writer"
	DestinationStream   DestinationType = "stream"
	DestinationDatabase DestinationType = "database"
)

// TrimType represents types of string trimming
type TrimType string

const (
	TrimBoth   TrimType = "both"
	TrimLeft   TrimType = "left"
	TrimRight  TrimType = "right"
	TrimCustom TrimType = "custom"
)

// SplitType represents types of string splitting
type SplitType string

const (
	SplitString     SplitType = "string"
	SplitRegex      SplitType = "regex"
	SplitLines      SplitType = "lines"
	SplitWords      SplitType = "words"
	SplitWhitespace SplitType = "whitespace"
)

// QuoteType represents types of string quoting
type QuoteType string

const (
	QuoteDouble   QuoteType = "double"
	QuoteSingle   QuoteType = "single"
	QuoteBacktick QuoteType = "backtick"
	QuoteCustom   QuoteType = "custom"
)

// LineEndingType represents line ending types
type LineEndingType string

const (
	LineEndingLF   LineEndingType = "lf"   // Unix/Linux (\n)
	LineEndingCRLF LineEndingType = "crlf" // Windows (\r\n)
	LineEndingCR   LineEndingType = "cr"   // Classic Mac (\r)
)

// Severity represents severity levels
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// OperationType represents types of string operations
type OperationType string

const (
	OperationValidate  OperationType = "validate"
	OperationSanitize  OperationType = "sanitize"
	OperationTransform OperationType = "transform"
	OperationFormat    OperationType = "format"
	OperationAnalyze   OperationType = "analyze"
	OperationGenerate  OperationType = "generate"
	OperationCompare   OperationType = "compare"
	OperationSearch    OperationType = "search"
	OperationEncode    OperationType = "encode"
	OperationDecode    OperationType = "decode"
)

// CharacterSet represents character sets for generation
type CharacterSet string

const (
	CharsetAlphabetic   CharacterSet = "alphabetic"
	CharsetNumeric      CharacterSet = "numeric"
	CharsetAlphanumeric CharacterSet = "alphanumeric"
	CharsetSymbols      CharacterSet = "symbols"
	CharsetPrintable    CharacterSet = "printable"
	CharsetASCII        CharacterSet = "ascii"
	CharsetCustom       CharacterSet = "custom"
)

// DistanceAlgorithm represents string distance algorithms
type DistanceAlgorithm string

const (
	AlgorithmLevenshtein DistanceAlgorithm = "levenshtein"
	AlgorithmHamming     DistanceAlgorithm = "hamming"
	AlgorithmJaro        DistanceAlgorithm = "jaro"
	AlgorithmJaroWinkler DistanceAlgorithm = "jaro_winkler"
	AlgorithmDamerau     DistanceAlgorithm = "damerau"
)

// CompareAlgorithm represents comparison algorithms
type CompareAlgorithm string

const (
	CompareExact      CompareAlgorithm = "exact"
	CompareFuzzy      CompareAlgorithm = "fuzzy"
	ComparePhonetic   CompareAlgorithm = "phonetic"
	CompareSemantic   CompareAlgorithm = "semantic"
	CompareStructural CompareAlgorithm = "structural"
)

// ComplexityLevel represents complexity levels
type ComplexityLevel string

const (
	ComplexityLow      ComplexityLevel = "low"
	ComplexityMedium   ComplexityLevel = "medium"
	ComplexityHigh     ComplexityLevel = "high"
	ComplexityVeryHigh ComplexityLevel = "very_high"
)

// TextDirection represents text direction
type TextDirection string

const (
	DirectionLTR TextDirection = "ltr" // Left to Right
	DirectionRTL TextDirection = "rtl" // Right to Left
	DirectionTTB TextDirection = "ttb" // Top to Bottom
)

// Sentiment represents sentiment types
type Sentiment string

const (
	SentimentPositive Sentiment = "positive"
	SentimentNegative Sentiment = "negative"
	SentimentNeutral  Sentiment = "neutral"
	SentimentMixed    Sentiment = "mixed"
)

// ThreatLevel represents security threat levels
type ThreatLevel string

const (
	ThreatNone     ThreatLevel = "none"
	ThreatLow      ThreatLevel = "low"
	ThreatMedium   ThreatLevel = "medium"
	ThreatHigh     ThreatLevel = "high"
	ThreatCritical ThreatLevel = "critical"
)

// SecurityIssueType represents types of security issues
type SecurityIssueType string

const (
	IssueSQL       SecurityIssueType = "sql_injection"
	IssueXSS       SecurityIssueType = "xss"
	IssueShellMeta SecurityIssueType = "shell_metacharacters"
	IssueSecrets   SecurityIssueType = "secrets"
	IssueMalware   SecurityIssueType = "malware"
	IssuePhishing  SecurityIssueType = "phishing"
	IssueEncoding  SecurityIssueType = "encoding_attack"
)

// SecurityEventType represents types of security events
type SecurityEventType string

const (
	EventSuspiciousInput   SecurityEventType = "suspicious_input"
	EventPolicyViolation   SecurityEventType = "policy_violation"
	EventAnomalousPattern  SecurityEventType = "anomalous_pattern"
	EventSecretDetected    SecurityEventType = "secret_detected"
	EventMalwareDetected   SecurityEventType = "malware_detected"
	EventRateLimitExceeded SecurityEventType = "rate_limit_exceeded"
)

// QualityGrade represents quality grades
type QualityGrade string

const (
	GradeA QualityGrade = "A"
	GradeB QualityGrade = "B"
	GradeC QualityGrade = "C"
	GradeD QualityGrade = "D"
	GradeF QualityGrade = "F"
)

// DiffType represents types of string differences
type DiffType string

const (
	DiffInsert  DiffType = "insert"
	DiffDelete  DiffType = "delete"
	DiffReplace DiffType = "replace"
	DiffEqual   DiffType = "equal"
)

// TransformType represents types of transformations
type TransformType string

const (
	TransformCase      TransformType = "case"
	TransformTrim      TransformType = "trim"
	TransformReplace   TransformType = "replace"
	TransformFormat    TransformType = "format"
	TransformSanitize  TransformType = "sanitize"
	TransformEncode    TransformType = "encode"
	TransformNormalize TransformType = "normalize"
)

// EncodingType represents encoding types
type EncodingType string

const (
	EncodingBase64  EncodingType = "base64"
	EncodingHex     EncodingType = "hex"
	EncodingURL     EncodingType = "url"
	EncodingHTML    EncodingType = "html"
	EncodingJSON    EncodingType = "json"
	EncodingXML     EncodingType = "xml"
	EncodingUnicode EncodingType = "unicode"
)

// UUIDVersion represents UUID versions
type UUIDVersion string

const (
	UUIDv1 UUIDVersion = "v1"
	UUIDv3 UUIDVersion = "v3"
	UUIDv4 UUIDVersion = "v4"
	UUIDv5 UUIDVersion = "v5"
)

// HashAlgorithm represents hash algorithms
type HashAlgorithm string

const (
	HashMD5    HashAlgorithm = "md5"
	HashSHA1   HashAlgorithm = "sha1"
	HashSHA256 HashAlgorithm = "sha256"
	HashSHA512 HashAlgorithm = "sha512"
	HashBcrypt HashAlgorithm = "bcrypt"
)

// TimeUnit represents time units for formatting
type TimeUnit string

const (
	UnitSeconds      TimeUnit = "seconds"
	UnitMinutes      TimeUnit = "minutes"
	UnitHours        TimeUnit = "hours"
	UnitDays         TimeUnit = "days"
	UnitWeeks        TimeUnit = "weeks"
	UnitMonths       TimeUnit = "months"
	UnitYears        TimeUnit = "years"
	UnitMilliseconds TimeUnit = "milliseconds"
	UnitMicroseconds TimeUnit = "microseconds"
	UnitNanoseconds  TimeUnit = "nanoseconds"
)

// CompressionType represents compression types
type CompressionType string

const (
	CompressionNone  CompressionType = "none"
	CompressionGzip  CompressionType = "gzip"
	CompressionZip   CompressionType = "zip"
	CompressionBzip2 CompressionType = "bzip2"
	CompressionLzma  CompressionType = "lzma"
)

// SortOrder represents sort order
type SortOrder string

const (
	SortAsc  SortOrder = "asc"
	SortDesc SortOrder = "desc"
)
