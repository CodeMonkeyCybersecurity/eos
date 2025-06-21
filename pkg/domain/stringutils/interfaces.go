// Package stringutils defines domain interfaces for string manipulation and validation operations
package stringutils

import (
	"context"
	"io"
	"regexp"
)

// StringUtilsService provides the main domain service for string operations
type StringUtilsService interface {
	// Basic string operations
	Trim(ctx context.Context, input string, options *TrimOptions) (string, error)
	Split(ctx context.Context, input string, config *SplitConfig) ([]string, error)
	Join(ctx context.Context, parts []string, separator string) (string, error)
	Replace(ctx context.Context, input string, config *ReplaceConfig) (string, error)
	
	// Case operations
	ToUpper(ctx context.Context, input string) (string, error)
	ToLower(ctx context.Context, input string) (string, error)
	ToTitle(ctx context.Context, input string) (string, error)
	ToCamelCase(ctx context.Context, input string) (string, error)
	ToSnakeCase(ctx context.Context, input string) (string, error)
	ToKebabCase(ctx context.Context, input string) (string, error)
	
	// Validation operations
	ValidateString(ctx context.Context, input string, rules *ValidationRules) (*ValidationResult, error)
	ValidateEmail(ctx context.Context, email string) (*ValidationResult, error)
	ValidateURL(ctx context.Context, url string) (*ValidationResult, error)
	ValidateIP(ctx context.Context, ip string) (*ValidationResult, error)
	ValidateDomain(ctx context.Context, domain string) (*ValidationResult, error)
	ValidateUsername(ctx context.Context, username string) (*ValidationResult, error)
	
	// Sanitization operations
	Sanitize(ctx context.Context, input string, options *SanitizeOptions) (string, error)
	Redact(ctx context.Context, input string, patterns []string) (string, error)
	RemoveShellMetacharacters(ctx context.Context, input string) (string, error)
	EscapeShell(ctx context.Context, input string) (string, error)
	
	// Path operations
	ExpandPath(ctx context.Context, path string) (string, error)
	SplitPath(ctx context.Context, pathList string) ([]string, error)
	ValidatePath(ctx context.Context, path string, options *PathValidationOptions) (*ValidationResult, error)
	NormalizePath(ctx context.Context, path string) (string, error)
	
	// Formatting operations
	Quote(ctx context.Context, input string, quoteType QuoteType) (string, error)
	Unquote(ctx context.Context, input string) (string, error)
	PadLeft(ctx context.Context, input string, length int, padChar rune) (string, error)
	PadRight(ctx context.Context, input string, length int, padChar rune) (string, error)
	Truncate(ctx context.Context, input string, maxLength int, ellipsis string) (string, error)
	
	// Pattern matching operations
	Match(ctx context.Context, pattern string, input string) (bool, error)
	FindAll(ctx context.Context, pattern string, input string) ([]string, error)
	ReplacePattern(ctx context.Context, pattern string, input string, replacement string) (string, error)
	
	// Encoding operations
	Base64Encode(ctx context.Context, input string) (string, error)
	Base64Decode(ctx context.Context, encoded string) (string, error)
	URLEncode(ctx context.Context, input string) (string, error)
	URLDecode(ctx context.Context, encoded string) (string, error)
	HTMLEscape(ctx context.Context, input string) (string, error)
	HTMLUnescape(ctx context.Context, escaped string) (string, error)
	
	// Conversion operations
	ToBytes(ctx context.Context, input string, encoding StringEncoding) ([]byte, error)
	FromBytes(ctx context.Context, data []byte, encoding StringEncoding) (string, error)
	ConvertEncoding(ctx context.Context, input string, from, to StringEncoding) (string, error)
	
	// Analysis operations
	Analyze(ctx context.Context, input string) (*StringAnalysis, error)
	Compare(ctx context.Context, str1, str2 string, options *CompareOptions) (*CompareResult, error)
	CalculateDistance(ctx context.Context, str1, str2 string, algorithm DistanceAlgorithm) (int, error)
	
	// Generation operations
	GenerateRandom(ctx context.Context, config *RandomStringConfig) (string, error)
	GenerateSlug(ctx context.Context, input string, options *SlugOptions) (string, error)
	GeneratePassword(ctx context.Context, config *PasswordConfig) (string, error)
}

// StringValidator provides string validation operations
type StringValidator interface {
	ValidateFormat(ctx context.Context, input string, format StringFormat) (*ValidationResult, error)
	ValidateLength(ctx context.Context, input string, min, max int) (*ValidationResult, error)
	ValidatePattern(ctx context.Context, input string, pattern *regexp.Regexp) (*ValidationResult, error)
	ValidateCharset(ctx context.Context, input string, allowedChars string) (*ValidationResult, error)
	ValidateBlacklist(ctx context.Context, input string, blacklist []string) (*ValidationResult, error)
	ValidateWhitelist(ctx context.Context, input string, whitelist []string) (*ValidationResult, error)
	CreateValidationRules(ctx context.Context, config *RuleConfig) (*ValidationRules, error)
}

// StringSanitizer provides string sanitization operations
type StringSanitizer interface {
	RemoveControlChars(ctx context.Context, input string) (string, error)
	RemoveNonPrintable(ctx context.Context, input string) (string, error)
	RemoveEmojis(ctx context.Context, input string) (string, error)
	RemoveHTML(ctx context.Context, input string) (string, error)
	RemoveSQL(ctx context.Context, input string) (string, error)
	RemoveJavaScript(ctx context.Context, input string) (string, error)
	NormalizeWhitespace(ctx context.Context, input string) (string, error)
	NormalizeLineEndings(ctx context.Context, input string, ending LineEndingType) (string, error)
}

// StringFormatter provides string formatting operations
type StringFormatter interface {
	FormatTemplate(ctx context.Context, template string, data map[string]interface{}) (string, error)
	FormatPlural(ctx context.Context, count int, singular, plural string) (string, error)
	FormatBytes(ctx context.Context, bytes int64, precision int) (string, error)
	FormatDuration(ctx context.Context, duration int64, unit TimeUnit) (string, error)
	FormatNumber(ctx context.Context, number float64, options *NumberFormatOptions) (string, error)
	FormatCurrency(ctx context.Context, amount float64, currency string) (string, error)
}

// StringTransformer provides string transformation operations
type StringTransformer interface {
	Transform(ctx context.Context, input string, operations []TransformOperation) (string, error)
	ApplyRules(ctx context.Context, input string, rules *TransformRules) (string, error)
	Batch(ctx context.Context, inputs []string, operation TransformOperation) ([]string, error)
}

// PatternMatcher provides pattern matching operations
type PatternMatcher interface {
	CompilePattern(ctx context.Context, pattern string, flags PatternFlags) (*CompiledPattern, error)
	MatchPattern(ctx context.Context, pattern *CompiledPattern, input string) (*MatchResult, error)
	FindMatches(ctx context.Context, pattern *CompiledPattern, input string) ([]*MatchResult, error)
	ReplaceMatches(ctx context.Context, pattern *CompiledPattern, input string, replacement string) (string, error)
	ValidatePattern(ctx context.Context, pattern string) (*PatternValidation, error)
}

// StringEncoder provides encoding and decoding operations
type StringEncoder interface {
	Encode(ctx context.Context, input string, encoding EncodingType) (string, error)
	Decode(ctx context.Context, input string, encoding EncodingType) (string, error)
	DetectEncoding(ctx context.Context, input []byte) (StringEncoding, float64, error)
	ConvertBetweenEncodings(ctx context.Context, input string, from, to StringEncoding) (string, error)
	SupportedEncodings() []EncodingType
}

// StringGenerator provides string generation operations
type StringGenerator interface {
	GenerateRandomString(ctx context.Context, config *RandomStringConfig) (string, error)
	GenerateUUID(ctx context.Context, version UUIDVersion) (string, error)
	GenerateHash(ctx context.Context, input string, algorithm HashAlgorithm) (string, error)
	GenerateSecureToken(ctx context.Context, length int) (string, error)
	GenerateHumanReadable(ctx context.Context, config *HumanReadableConfig) (string, error)
}

// StringAnalyzer provides string analysis operations
type StringAnalyzer interface {
	AnalyzeContent(ctx context.Context, input string) (*ContentAnalysis, error)
	AnalyzeComplexity(ctx context.Context, input string) (*ComplexityAnalysis, error)
	AnalyzeLanguage(ctx context.Context, input string) (*LanguageAnalysis, error)
	AnalyzeSentiment(ctx context.Context, input string) (*SentimentAnalysis, error)
	FindSimilarities(ctx context.Context, input string, candidates []string) ([]*SimilarityResult, error)
}

// StringReader provides string reading operations from various sources
type StringReader interface {
	ReadFromFile(ctx context.Context, filepath string, encoding StringEncoding) (string, error)
	ReadFromReader(ctx context.Context, reader io.Reader, encoding StringEncoding) (string, error)
	ReadFromURL(ctx context.Context, url string, encoding StringEncoding) (string, error)
	ReadLines(ctx context.Context, source StringSource, maxLines int) ([]string, error)
	ReadChunks(ctx context.Context, source StringSource, chunkSize int) ([]string, error)
}

// StringWriter provides string writing operations to various destinations
type StringWriter interface {
	WriteToFile(ctx context.Context, content string, filepath string, encoding StringEncoding) error
	WriteToWriter(ctx context.Context, content string, writer io.Writer, encoding StringEncoding) error
	WriteLines(ctx context.Context, lines []string, destination StringDestination) error
	AppendToFile(ctx context.Context, content string, filepath string, encoding StringEncoding) error
}

// StringRepository manages persistent string data
type StringRepository interface {
	SaveStringData(ctx context.Context, data *StringData) error
	GetStringData(ctx context.Context, id string) (*StringData, error)
	ListStringData(ctx context.Context, filter *StringFilter) ([]*StringData, error)
	DeleteStringData(ctx context.Context, id string) error
	UpdateStringData(ctx context.Context, id string, data *StringData) error
	SearchStringData(ctx context.Context, query string, options *SearchOptions) ([]*StringData, error)
}

// StringAuditRepository tracks string operations for audit purposes
type StringAuditRepository interface {
	RecordOperation(ctx context.Context, operation *StringOperation) error
	GetOperationHistory(ctx context.Context, filter *OperationFilter) ([]*StringOperation, error)
	GetStatistics(ctx context.Context, timeRange *TimeRange) (*OperationStatistics, error)
	GetSecurityEvents(ctx context.Context, filter *SecurityEventFilter) ([]*SecurityEvent, error)
}