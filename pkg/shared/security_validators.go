package shared

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SecurityValidators provides comprehensive input validation for security-critical operations
type SecurityValidators struct {
	maxInputLength int
	strictMode     bool
}

// NewSecurityValidators creates a new security validator with default settings
func NewSecurityValidators() *SecurityValidators {
	return &SecurityValidators{
		maxInputLength: 8192,
		strictMode:     false,
	}
}

// NewStrictSecurityValidators creates validators with strict security settings
func NewStrictSecurityValidators() *SecurityValidators {
	return &SecurityValidators{
		maxInputLength: 1024,
		strictMode:     true,
	}
}

// ValidateNetworkInput validates network-related inputs (IPs, ports, hostnames)
func (sv *SecurityValidators) ValidateNetworkInput(input, fieldName string) error {
	if input == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}

	if len(input) > sv.maxInputLength {
		return fmt.Errorf("%s too long: %d characters (max %d)", fieldName, len(input), sv.maxInputLength)
	}

	// Check for dangerous patterns in network input
	dangerousPatterns := []string{
		"javascript:", "data:", "file:", "ftp:",
		"<script>", "$(", "`", ";", "&", "|",
		"0.0.0.0", "shared.GetInternalHostname", "localhost",
		"169.254.", "10.", "192.168.", "172.",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(strings.ToLower(input), pattern) {
			return fmt.Errorf("%s contains dangerous pattern: %s", fieldName, pattern)
		}
	}

	return nil
}

// ValidateIPAddress validates IP addresses (both IPv4 and IPv6)
func (sv *SecurityValidators) ValidateIPAddress(ip, fieldName string) error {
	if ip == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("%s is not a valid IP address", fieldName)
	}

	// Check for dangerous IP ranges in strict mode
	if sv.strictMode {
		if parsed.IsLoopback() {
			return fmt.Errorf("%s cannot be a loopback address", fieldName)
		}
		if parsed.IsPrivate() {
			return fmt.Errorf("%s cannot be a private address", fieldName)
		}
		if parsed.IsMulticast() {
			return fmt.Errorf("%s cannot be a multicast address", fieldName)
		}
	}

	return nil
}

// ValidatePort validates port numbers
func (sv *SecurityValidators) ValidatePort(portStr, fieldName string) error {
	if portStr == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("%s must be a valid number", fieldName)
	}

	if port < 1 || port > 65535 {
		return fmt.Errorf("%s must be between 1 and 65535", fieldName)
	}

	// Check for privileged ports in strict mode
	if sv.strictMode && port < 1024 {
		return fmt.Errorf("%s cannot use privileged port %d", fieldName, port)
	}

	return nil
}

// ValidateHostname validates hostnames and domain names
func (sv *SecurityValidators) ValidateHostname(hostname, fieldName string) error {
	if hostname == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}

	if len(hostname) > 253 {
		return fmt.Errorf("%s too long: %d characters (max 253)", fieldName, len(hostname))
	}

	// Basic hostname validation
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	if !hostnameRegex.MatchString(hostname) {
		return fmt.Errorf("%s contains invalid characters", fieldName)
	}

	// Check for dangerous patterns
	if strings.Contains(hostname, "..") {
		return fmt.Errorf("%s cannot contain consecutive dots", fieldName)
	}

	if strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return fmt.Errorf("%s cannot start or end with a dot", fieldName)
	}

	// Validate each label
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return fmt.Errorf("%s contains empty label", fieldName)
		}
		if len(label) > 63 {
			return fmt.Errorf("%s label too long: %s", fieldName, label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("%s label cannot start or end with hyphen: %s", fieldName, label)
		}
	}

	return nil
}

// ValidateURL validates URLs with security considerations
func (sv *SecurityValidators) ValidateURL(urlStr, fieldName string) error {
	if urlStr == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}

	if len(urlStr) > sv.maxInputLength {
		return fmt.Errorf("%s too long: %d characters (max %d)", fieldName, len(urlStr), sv.maxInputLength)
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", fieldName, err)
	}

	// Check allowed schemes
	allowedSchemes := []string{"http", "https"}
	if sv.strictMode {
		allowedSchemes = []string{"https"} // HTTPS only in strict mode
	}

	schemeAllowed := false
	for _, scheme := range allowedSchemes {
		if parsed.Scheme == scheme {
			schemeAllowed = true
			break
		}
	}

	if !schemeAllowed {
		return fmt.Errorf("%s uses disallowed scheme: %s", fieldName, parsed.Scheme)
	}

	// Validate hostname if present
	if parsed.Host != "" {
		err := sv.ValidateHostname(parsed.Hostname(), fieldName+" hostname")
		if err != nil {
			return err
		}
	}

	// Check for dangerous patterns in URL
	dangerousPatterns := []string{
		"javascript:", "data:", "file:", "ftp:",
		"<script>", "$(", "`", ";", "&",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(strings.ToLower(urlStr), pattern) {
			return fmt.Errorf("%s contains dangerous pattern: %s", fieldName, pattern)
		}
	}

	return nil
}

// ValidateEmail validates email addresses
func (sv *SecurityValidators) ValidateEmail(email, fieldName string) error {
	if email == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}

	if len(email) > 254 {
		return fmt.Errorf("%s too long: %d characters (max 254)", fieldName, len(email))
	}

	// Basic email regex
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("%s is not a valid email address", fieldName)
	}

	// Check for email injection patterns
	dangerousPatterns := []string{
		"\n", "\r", "\t", "bcc:", "cc:", "to:", "from:",
		"content-type:", "mime-version:", "subject:",
	}

	lower := strings.ToLower(email)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			return fmt.Errorf("%s contains dangerous pattern: %s", fieldName, pattern)
		}
	}

	return nil
}

// ValidateFilename validates filenames for security
func (sv *SecurityValidators) ValidateFilename(filename, fieldName string) error {
	if filename == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}

	if len(filename) > 255 {
		return fmt.Errorf("%s too long: %d characters (max 255)", fieldName, len(filename))
	}

	// Check for dangerous characters
	dangerousChars := []string{
		"/", "\\", ":", "*", "?", "\"", "<", ">", "|",
		"\x00", "\x01", "\x02", "\x03", "\x04", "\x05",
	}

	for _, char := range dangerousChars {
		if strings.Contains(filename, char) {
			return fmt.Errorf("%s contains dangerous character: %s", fieldName, char)
		}
	}

	// Check for dangerous filenames
	dangerousNames := []string{
		".", "..", "con", "prn", "aux", "nul",
		"com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
		"lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
	}

	lowerFilename := strings.ToLower(filename)
	for _, dangerous := range dangerousNames {
		if lowerFilename == dangerous {
			return fmt.Errorf("%s is a reserved filename: %s", fieldName, filename)
		}
	}

	// Check for hidden files in strict mode
	if sv.strictMode && strings.HasPrefix(filename, ".") {
		return fmt.Errorf("%s cannot be a hidden file", fieldName)
	}

	return nil
}

// ValidateUsername validates usernames
func (sv *SecurityValidators) ValidateUsername(username, fieldName string) error {
	if username == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}

	if len(username) < 2 {
		return fmt.Errorf("%s too short: %d characters (min 2)", fieldName, len(username))
	}

	if len(username) > 64 {
		return fmt.Errorf("%s too long: %d characters (max 64)", fieldName, len(username))
	}

	// Username should start with letter
	if !unicode.IsLetter(rune(username[0])) {
		return fmt.Errorf("%s must start with a letter", fieldName)
	}

	// Check allowed characters
	for _, r := range username {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' && r != '.' {
			return fmt.Errorf("%s contains invalid character: %c", fieldName, r)
		}
	}

	// Check for dangerous usernames
	dangerousUsernames := []string{
		"root", "admin", "administrator", "user", "guest", "test",
		"service", "daemon", "system", "operator", "supervisor",
	}

	lower := strings.ToLower(username)
	for _, dangerous := range dangerousUsernames {
		if lower == dangerous {
			return fmt.Errorf("%s cannot use reserved username: %s", fieldName, username)
		}
	}

	return nil
}

// ValidatePassword validates password strength
func (sv *SecurityValidators) ValidatePassword(password, fieldName string) error {
	if password == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}

	minLength := 8
	if sv.strictMode {
		minLength = 12
	}

	if len(password) < minLength {
		return fmt.Errorf("%s too short: %d characters (min %d)", fieldName, len(password), minLength)
	}

	if len(password) > 128 {
		return fmt.Errorf("%s too long: %d characters (max 128)", fieldName, len(password))
	}

	// Check character diversity
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSpecial := false

	for _, r := range password {
		if unicode.IsLower(r) {
			hasLower = true
		} else if unicode.IsUpper(r) {
			hasUpper = true
		} else if unicode.IsDigit(r) {
			hasDigit = true
		} else if unicode.IsPunct(r) || unicode.IsSymbol(r) {
			hasSpecial = true
		}
	}

	requiredTypes := 3
	if sv.strictMode {
		requiredTypes = 4
	}

	actualTypes := 0
	if hasLower {
		actualTypes++
	}
	if hasUpper {
		actualTypes++
	}
	if hasDigit {
		actualTypes++
	}
	if hasSpecial {
		actualTypes++
	}

	if actualTypes < requiredTypes {
		return fmt.Errorf("%s must contain at least %d different character types", fieldName, requiredTypes)
	}

	// Check for common weak passwords
	weakPasswords := []string{
		"password", "123456", "qwerty", "admin", "letmein", "welcome",
		"monkey", "dragon", "sunshine", "princess", "football",
	}

	lower := strings.ToLower(password)
	for _, weak := range weakPasswords {
		if strings.Contains(lower, weak) {
			return fmt.Errorf("%s contains common weak pattern: %s", fieldName, weak)
		}
	}

	return nil
}

// ValidateJSONInput validates JSON input for security issues
func (sv *SecurityValidators) ValidateJSONInput(jsonStr, fieldName string) error {
	if len(jsonStr) > sv.maxInputLength {
		return fmt.Errorf("%s too long: %d characters (max %d)", fieldName, len(jsonStr), sv.maxInputLength)
	}

	if !utf8.ValidString(jsonStr) {
		return fmt.Errorf("%s contains invalid UTF-8", fieldName)
	}

	// Check for dangerous patterns in JSON
	dangerousPatterns := []string{
		"__proto__", "constructor", "prototype",
		"<script>", "javascript:", "onerror=", "onclick=",
		"'; DROP", "UNION SELECT", "$(", "`",
	}

	lower := strings.ToLower(jsonStr)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			return fmt.Errorf("%s contains dangerous pattern: %s", fieldName, pattern)
		}
	}

	return nil
}

// ValidateCommandArgument validates command line arguments
func (sv *SecurityValidators) ValidateCommandArgument(arg, fieldName string) error {
	if len(arg) > sv.maxInputLength {
		return fmt.Errorf("%s too long: %d characters (max %d)", fieldName, len(arg), sv.maxInputLength)
	}

	if !utf8.ValidString(arg) {
		return fmt.Errorf("%s contains invalid UTF-8", fieldName)
	}

	// Check for command injection patterns
	dangerousPatterns := []string{
		";", "|", "&", "$(", "`", "&&", "||", ">", "<",
		"rm -rf", "cat /etc/", "/bin/sh", "/bin/bash",
		"wget ", "curl ", "nc ", "netcat",
	}

	lower := strings.ToLower(arg)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			return fmt.Errorf("%s contains dangerous pattern: %s", fieldName, pattern)
		}
	}

	// Check for null bytes
	if strings.Contains(arg, "\x00") {
		return fmt.Errorf("%s contains null bytes", fieldName)
	}

	return nil
}

// Package-level validators for convenience
var DefaultValidators = NewSecurityValidators()
var StrictValidators = NewStrictSecurityValidators()

// Convenience functions using default validators
func ValidateSecureNetworkInput(input, fieldName string) error {
	return DefaultValidators.ValidateNetworkInput(input, fieldName)
}

func ValidateSecureIPAddress(ip, fieldName string) error {
	return DefaultValidators.ValidateIPAddress(ip, fieldName)
}

func ValidateSecurePort(port, fieldName string) error {
	return DefaultValidators.ValidatePort(port, fieldName)
}

func ValidateSecureHostname(hostname, fieldName string) error {
	return DefaultValidators.ValidateHostname(hostname, fieldName)
}

func ValidateSecureURL(url, fieldName string) error {
	return DefaultValidators.ValidateURL(url, fieldName)
}

func ValidateSecureEmail(email, fieldName string) error {
	return DefaultValidators.ValidateEmail(email, fieldName)
}

func ValidateSecureFilename(filename, fieldName string) error {
	return DefaultValidators.ValidateFilename(filename, fieldName)
}

func ValidateSecureUsername(username, fieldName string) error {
	return DefaultValidators.ValidateUsername(username, fieldName)
}

func ValidateSecurePassword(password, fieldName string) error {
	return DefaultValidators.ValidatePassword(password, fieldName)
}

func ValidateSecureJSONInput(jsonStr, fieldName string) error {
	return DefaultValidators.ValidateJSONInput(jsonStr, fieldName)
}

func ValidateSecureCommandArgument(arg, fieldName string) error {
	return DefaultValidators.ValidateCommandArgument(arg, fieldName)
}
