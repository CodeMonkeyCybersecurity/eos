package crypto

import (
	"fmt"
	"regexp"
	"strings"
)

// Security constants for input validation
const (
	MaxDomainLength = 253  // RFC 1035
	MaxEmailLength  = 254  // RFC 5321
	MaxAppNameLength = 63  // DNS label limit
)

// Secure regular expressions for validation
var (
	// ValidDomainPattern matches valid domain names according to RFC standards
	// Allows letters, numbers, hyphens, and dots. No consecutive dots or hyphens at start/end
	ValidDomainPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	
	// ValidEmailPattern matches basic email format (simplified for security)
	// More restrictive than full RFC 5322 to prevent injection attacks
	ValidEmailPattern = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	
	// ValidAppNamePattern matches application names (DNS label format)
	// Letters, numbers, hyphens only. No hyphens at start/end
	ValidAppNamePattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
)

// Dangerous characters that could be used for command injection
var dangerousChars = []string{
	";", "&", "|", "$", "`", "\\", "'", "\"", 
	"\n", "\r", "\t", " ", "<", ">", "*", "?",
	"(", ")", "[", "]", "{", "}", "!", "~",
}

// ValidateDomainName performs comprehensive validation of domain names for certificate generation
func ValidateDomainName(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain name cannot be empty")
	}
	
	// Check length
	if len(domain) > MaxDomainLength {
		return fmt.Errorf("domain name too long: %d characters (max %d)", len(domain), MaxDomainLength)
	}
	
	// Check for dangerous characters that could be used for injection
	for _, char := range dangerousChars {
		if strings.Contains(domain, char) {
			return fmt.Errorf("domain name contains invalid character: %s", char)
		}
	}
	
	// Check against regex pattern
	if !ValidDomainPattern.MatchString(domain) {
		return fmt.Errorf("domain name format is invalid: %s", domain)
	}
	
	// Additional security checks
	if strings.Contains(domain, "..") {
		return fmt.Errorf("domain name cannot contain consecutive dots")
	}
	
	if strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") {
		return fmt.Errorf("domain name cannot start or end with hyphen")
	}
	
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return fmt.Errorf("domain name cannot start or end with dot")
	}
	
	// Check for localhost and internal domains (security concern)
	lowercaseDomain := strings.ToLower(domain)
	suspiciousDomains := []string{
		"localhost", "127.0.0.1", "::1", "0.0.0.0",
		"internal", "local", "test", "example.com",
		"*.local", "*.internal",
	}
	
	for _, suspicious := range suspiciousDomains {
		if lowercaseDomain == suspicious || strings.Contains(lowercaseDomain, suspicious) {
			return fmt.Errorf("domain name contains suspicious pattern: %s", suspicious)
		}
	}
	
	return nil
}

// ValidateEmailAddress performs comprehensive validation of email addresses
func ValidateEmailAddress(email string) error {
	if email == "" {
		return fmt.Errorf("email address cannot be empty")
	}
	
	// Check length
	if len(email) > MaxEmailLength {
		return fmt.Errorf("email address too long: %d characters (max %d)", len(email), MaxEmailLength)
	}
	
	// Check for dangerous characters
	for _, char := range dangerousChars {
		if strings.Contains(email, char) {
			// Allow some characters that are valid in emails
			if char != "." && char != "+" && char != "-" && char != "_" {
				return fmt.Errorf("email address contains invalid character: %s", char)
			}
		}
	}
	
	// Check against regex pattern
	if !ValidEmailPattern.MatchString(email) {
		return fmt.Errorf("email address format is invalid: %s", email)
	}
	
	// Additional security checks
	if strings.Contains(email, "..") {
		return fmt.Errorf("email address cannot contain consecutive dots")
	}
	
	// Split email to validate parts separately
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return fmt.Errorf("email address must contain exactly one @ symbol")
	}
	
	localPart, domainPart := parts[0], parts[1]
	
	// Validate local part (before @)
	if len(localPart) == 0 || len(localPart) > 64 {
		return fmt.Errorf("email local part must be 1-64 characters")
	}
	
	if strings.HasPrefix(localPart, ".") || strings.HasSuffix(localPart, ".") {
		return fmt.Errorf("email local part cannot start or end with dot")
	}
	
	// Validate domain part using our domain validator
	if err := ValidateDomainName(domainPart); err != nil {
		return fmt.Errorf("email domain part invalid: %w", err)
	}
	
	return nil
}

// ValidateAppName performs validation of application names
func ValidateAppName(appName string) error {
	if appName == "" {
		return fmt.Errorf("application name cannot be empty")
	}
	
	// Check length
	if len(appName) > MaxAppNameLength {
		return fmt.Errorf("application name too long: %d characters (max %d)", len(appName), MaxAppNameLength)
	}
	
	// Check for dangerous characters
	for _, char := range dangerousChars {
		if strings.Contains(appName, char) {
			// Only allow hyphens as special characters in app names
			if char != "-" {
				return fmt.Errorf("application name contains invalid character: %s", char)
			}
		}
	}
	
	// Check against regex pattern
	if !ValidAppNamePattern.MatchString(appName) {
		return fmt.Errorf("application name format is invalid: %s", appName)
	}
	
	// Additional checks
	if strings.HasPrefix(appName, "-") || strings.HasSuffix(appName, "-") {
		return fmt.Errorf("application name cannot start or end with hyphen")
	}
	
	// Prevent reserved names
	reservedNames := []string{
		"admin", "root", "system", "daemon", "www", "ftp", "mail",
		"api", "app", "web", "db", "database", "cache", "redis",
		"vault", "consul", "docker", "kubernetes", "k8s",
	}
	
	lowerAppName := strings.ToLower(appName)
	for _, reserved := range reservedNames {
		if lowerAppName == reserved {
			return fmt.Errorf("application name '%s' is reserved", appName)
		}
	}
	
	return nil
}

// SanitizeInputForCommand performs final sanitization before command execution
// This is a belt-and-suspenders approach after validation
func SanitizeInputForCommand(input string) string {
	// Remove any null bytes
	input = strings.ReplaceAll(input, "\x00", "")
	
	// Remove any control characters
	var sanitized strings.Builder
	for _, r := range input {
		// Only allow printable ASCII characters and basic punctuation
		if (r >= 'a' && r <= 'z') || 
		   (r >= 'A' && r <= 'Z') || 
		   (r >= '0' && r <= '9') || 
		   r == '.' || r == '-' || r == '_' || r == '@' || r == '+' {
			sanitized.WriteRune(r)
		}
	}
	
	return sanitized.String()
}

// ValidateAllCertificateInputs validates all inputs for certificate generation
func ValidateAllCertificateInputs(appName, baseDomain, email string) error {
	// Validate each input individually
	if err := ValidateAppName(appName); err != nil {
		return fmt.Errorf("invalid application name: %w", err)
	}
	
	if err := ValidateDomainName(baseDomain); err != nil {
		return fmt.Errorf("invalid base domain: %w", err)
	}
	
	if err := ValidateEmailAddress(email); err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}
	
	// Validate the constructed FQDN
	fqdn := fmt.Sprintf("%s.%s", appName, baseDomain)
	if err := ValidateDomainName(fqdn); err != nil {
		return fmt.Errorf("invalid constructed FQDN '%s': %w", fqdn, err)
	}
	
	// Check total length of constructed domain
	if len(fqdn) > MaxDomainLength {
		return fmt.Errorf("constructed FQDN too long: %d characters (max %d)", len(fqdn), MaxDomainLength)
	}
	
	return nil
}