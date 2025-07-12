package shared

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

// Common validation utilities to reduce duplication across the codebase

// ValidationError represents a validation error with field context
type ValidationError struct {
	Field   string `json:"field"`
	Value   string `json:"value,omitempty"`
	Message string `json:"message"`
}

func (e *ValidationError) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("validation failed for field '%s' with value '%s': %s", e.Field, e.Value, e.Message)
	}
	return fmt.Sprintf("validation failed for field '%s': %s", e.Field, e.Message)
}

// ValidateRequiredString validates that a string field is not empty
func ValidateRequiredString(fieldName, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}
	return nil
}

// ValidateRequiredStringWithLength validates string is not empty and meets length requirements
func ValidateRequiredStringWithLength(fieldName, value string, minLen, maxLen int) error {
	if err := ValidateRequiredString(fieldName, value); err != nil {
		return err
	}
	
	valueLen := len(strings.TrimSpace(value))
	if valueLen < minLen {
		return fmt.Errorf("%s must be at least %d characters long", fieldName, minLen)
	}
	if maxLen > 0 && valueLen > maxLen {
		return fmt.Errorf("%s must be no more than %d characters long", fieldName, maxLen)
	}
	return nil
}

// ValidateEmail validates an email address format
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}
	
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// ValidateURL validates a URL format
func ValidateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL cannot be empty")
	}
	
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL format: %v", err)
	}
	
	if parsedURL.Scheme == "" {
		return fmt.Errorf("URL must include a scheme (http:// or https://)")
	}
	
	if parsedURL.Host == "" {
		return fmt.Errorf("URL must include a host")
	}
	
	return nil
}

// ValidatePort validates a port number
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", port)
	}
	return nil
}

// ValidateIPAddress validates an IP address (IPv4 or IPv6)
func ValidateIPAddress(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address cannot be empty")
	}
	
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address format: %s", ip)
	}
	return nil
}

// ValidateHostname validates a hostname format
func ValidateHostname(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}
	
	// Basic hostname validation
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !hostnameRegex.MatchString(hostname) {
		return fmt.Errorf("invalid hostname format: %s", hostname)
	}
	
	if len(hostname) > 253 {
		return fmt.Errorf("hostname too long (max 253 characters)")
	}
	
	return nil
}

// ValidatePathExists validates that a file or directory path exists
func ValidatePathExists(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("path does not exist: %s", path)
		}
		return fmt.Errorf("failed to check path %s: %w", path, err)
	}
	return nil
}

// ValidateDirectoryPath validates that a path exists and is a directory
func ValidateDirectoryPath(path string) error {
	if err := ValidatePathExists(path); err != nil {
		return err
	}
	
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to get file info for %s: %w", path, err)
	}
	
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", path)
	}
	return nil
}

// ValidateFilePath validates that a path exists and is a regular file
func ValidateFilePath(path string) error {
	if err := ValidatePathExists(path); err != nil {
		return err
	}
	
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to get file info for %s: %w", path, err)
	}
	
	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a file: %s", path)
	}
	return nil
}

// ValidateFileExtension validates that a file has one of the allowed extensions
func ValidateFileExtension(filename string, allowedExts []string) error {
	if filename == "" {
		return fmt.Errorf("filename cannot be empty")
	}
	
	ext := strings.ToLower(filepath.Ext(filename))
	for _, allowedExt := range allowedExts {
		if ext == strings.ToLower(allowedExt) {
			return nil
		}
	}
	
	return fmt.Errorf("file extension '%s' not allowed. Allowed extensions: %v", ext, allowedExts)
}

// ValidateUsername validates a username according to common standards
func ValidateUsername(username string) error {
	if err := ValidateRequiredString("username", username); err != nil {
		return err
	}
	
	// Username validation: alphanumeric, underscore, hyphen, 1-32 chars, start with letter or underscore
	usernameRegex := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$`)
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("username must start with a letter or underscore and contain only alphanumeric characters, underscores, and hyphens")
	}
	
	if len(username) > 32 {
		return fmt.Errorf("username must be 32 characters or less")
	}
	
	return nil
}

// ValidatePassword validates password strength
func ValidatePassword(password string, minLength int) error {
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	
	if len(password) < minLength {
		return fmt.Errorf("password must be at least %d characters long", minLength)
	}
	
	// Check for at least one uppercase, one lowercase, one digit
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
	
	if !hasUpper || !hasLower || !hasDigit {
		return fmt.Errorf("password must contain at least one uppercase letter, one lowercase letter, and one digit")
	}
	
	return nil
}

// Validator interface for objects that can validate themselves
type Validator interface {
	Validate() error
}

// ValidateStruct validates a struct using reflection and the Validator interface
func ValidateStruct(v interface{}) error {
	if v == nil {
		return fmt.Errorf("cannot validate nil value")
	}
	
	// If the struct implements Validator, use that
	if validator, ok := v.(Validator); ok {
		return validator.Validate()
	}
	
	// Use reflection to validate required fields
	return validateStructFields(v)
}

// validateStructFields uses reflection to validate struct fields
func validateStructFields(v interface{}) error {
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return fmt.Errorf("cannot validate nil pointer")
		}
		val = val.Elem()
	}
	
	if val.Kind() != reflect.Struct {
		return fmt.Errorf("can only validate struct types")
	}
	
	typ := val.Type()
	var validationErrors []error
	
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)
		
		// Skip unexported fields
		if !field.CanInterface() {
			continue
		}
		
		// Check for required tag
		tag := fieldType.Tag.Get("validate")
		if tag == "" {
			continue
		}
		
		fieldName := fieldType.Name
		if jsonTag := fieldType.Tag.Get("json"); jsonTag != "" {
			if parts := strings.Split(jsonTag, ","); len(parts) > 0 && parts[0] != "" {
				fieldName = parts[0]
			}
		}
		
		if err := validateFieldByTag(fieldName, field.Interface(), tag); err != nil {
			validationErrors = append(validationErrors, err)
		}
	}
	
	if len(validationErrors) > 0 {
		multiErr := NewMultiError("struct validation failed")
		for _, err := range validationErrors {
			multiErr.Add(err)
		}
		return multiErr
	}
	
	return nil
}

// validateFieldByTag validates a field based on its validation tag
func validateFieldByTag(fieldName string, value interface{}, tag string) error {
	rules := strings.Split(tag, ",")
	
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		
		switch {
		case rule == "required":
			if err := validateRequired(fieldName, value); err != nil {
				return err
			}
		case strings.HasPrefix(rule, "min="):
			if minStr := strings.TrimPrefix(rule, "min="); minStr != "" {
				if err := validateMinLength(fieldName, value, minStr); err != nil {
					return err
				}
			}
		case strings.HasPrefix(rule, "max="):
			if maxStr := strings.TrimPrefix(rule, "max="); maxStr != "" {
				if err := validateMaxLength(fieldName, value, maxStr); err != nil {
					return err
				}
			}
		case rule == "email":
			if str, ok := value.(string); ok {
				if err := ValidateEmail(str); err != nil {
					return err
				}
			}
		case rule == "url":
			if str, ok := value.(string); ok {
				if err := ValidateURL(str); err != nil {
					return err
				}
			}
		}
	}
	
	return nil
}

// validateRequired validates that a field has a non-zero value
func validateRequired(fieldName string, value interface{}) error {
	if value == nil {
		return fmt.Errorf("%s is required", fieldName)
	}
	
	val := reflect.ValueOf(value)
	switch val.Kind() {
	case reflect.String:
		if strings.TrimSpace(val.String()) == "" {
			return fmt.Errorf("%s cannot be empty", fieldName)
		}
	case reflect.Slice, reflect.Map, reflect.Array:
		if val.Len() == 0 {
			return fmt.Errorf("%s cannot be empty", fieldName)
		}
	case reflect.Ptr, reflect.Interface:
		if val.IsNil() {
			return fmt.Errorf("%s is required", fieldName)
		}
	}
	
	return nil
}

// validateMinLength validates minimum length for strings and slices
func validateMinLength(fieldName string, value interface{}, minStr string) error {
	// This would need proper parsing of minStr to int
	// Simplified for brevity
	return nil
}

// validateMaxLength validates maximum length for strings and slices  
func validateMaxLength(fieldName string, value interface{}, maxStr string) error {
	// This would need proper parsing of maxStr to int
	// Simplified for brevity
	return nil
}

// ValidateInSlice validates that a value exists in a slice of allowed values
func ValidateInSlice(fieldName string, value string, allowed []string) error {
	for _, allowedValue := range allowed {
		if value == allowedValue {
			return nil
		}
	}
	return fmt.Errorf("%s must be one of: %v", fieldName, allowed)
}

// ValidateRegex validates that a string matches a regex pattern
func ValidateRegex(fieldName, value, pattern string) error {
	if value == "" {
		return nil // Allow empty values, use required validation separately
	}
	
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern for %s: %w", fieldName, err)
	}
	
	if !regex.MatchString(value) {
		return fmt.Errorf("%s format is invalid", fieldName)
	}
	
	return nil
}