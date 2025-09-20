package shared

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzConfigParsing tests configuration parsing for injection attacks across multiple formats
func FuzzConfigParsing(f *testing.F) {
	// Add seed corpus with configuration injection attacks
	seeds := []string{
		// JSON injection attacks
		`{"key": "value"; rm -rf /; echo ""}`,
		`{"key": "$(whoami)"}`,
		`{"key": "value\"; system('rm -rf /'); //"}`,
		`{"key": "value\n\nmalicious: injection"}`,
		
		// YAML injection attacks
		"key: !!python/object/apply:os.system ['rm -rf /']",
		"key: !!map {? : }",
		"key: &anchor\n  <<: *anchor",
		"key: |\n  #!/bin/bash\n  rm -rf /",
		"key: value\n# malicious: $(whoami)",
		
		// TOML injection attacks
		`key = "value"\n[malicious]\ncommand = "rm -rf /"`,
		`key = """value\n[override]\nevil = true"""`,
		
		// ENV injection attacks
		"KEY=value\nMALICIOUS=$(whoami)",
		"KEY=value; rm -rf /",
		"KEY=value\x00INJECTED=evil",
		"KEY=value\nPATH=/malicious:$PATH",
		
		// Path traversal in config keys/values
		"../../../etc/passwd=value",
		"key=../../../etc/shadow",
		"..\\..\\..\\windows\\system32\\config\\sam=value",
		
		// Script injection in values
		"key=<script>alert(1)</script>",
		"key=javascript:alert(document.cookie)",
		"key='><script>alert(1)</script>",
		
		// Command substitution
		"key=`id`",
		"key=$(cat /etc/passwd)",
		"key=${malicious}",
		"key=%{evil}",
		
		// Buffer overflow attempts
		"key=" + strings.Repeat("A", 10000),
		strings.Repeat("k", 1000) + "=value",
		
		// Unicode attacks
		"kéy=válue", // Unicode in keys
		"key=vаlue", // Cyrillic 'а' instead of Latin 'a'
		"key=value\u202e", // Right-to-left override
		"key=value\ufeff", // BOM
		
		// Null byte injection
		"key=value\x00malicious",
		"key\x00malicious=value",
		
		// Multi-line injection
		"key=value\ninjected_key=malicious_value",
		"key=value\r\ninjected=evil",
		
		// Template injection
		"key={{.malicious}}",
		"key=${env:malicious}",
		"key=%{runtime:evil}",
		
		// Valid configurations (should pass)
		`{"valid": "json"}`,
		"valid: yaml",
		"valid = \"toml\"",
		"VALID=env",
		"",
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, configData string) {
		// Test JSON parsing
		if isJSONFormat(configData) {
			parsed, err := parseJSONConfig(configData)
			if err == nil {
				validateConfigData(t, parsed, "JSON")
			}
		}
		
		// Test YAML parsing
		if isYAMLFormat(configData) {
			parsed, err := parseYAMLConfig(configData)
			if err == nil {
				validateConfigData(t, parsed, "YAML")
			}
		}
		
		// Test TOML parsing
		if isTOMLFormat(configData) {
			parsed, err := parseTOMLConfig(configData)
			if err == nil {
				validateConfigData(t, parsed, "TOML")
			}
		}
		
		// Test ENV parsing
		parsed, err := parseENVConfig(configData)
		if err == nil {
			validateConfigData(t, parsed, "ENV")
		}
		
		// Test configuration sanitization
		sanitized := sanitizeConfigData(configData)
		if strings.Contains(sanitized, "\x00") {
			t.Error("Sanitized config contains null bytes")
		}
		
		// Test configuration validation
		isValid := validateConfigFormat(configData)
		_ = isValid
		
		// Test key/value extraction
		if len(configData) > 0 {
			keys := extractConfigKeys(configData)
			for _, key := range keys {
				if containsDangerousPatternsConfig(key) {
					t.Errorf("Config key contains dangerous pattern: %s", key)
				}
			}
		}
	})
}

// FuzzEnvironmentVariables tests environment variable parsing for injection
func FuzzEnvironmentVariables(f *testing.F) {
	seeds := []string{
		// Command injection in env vars
		"PATH=/malicious:$PATH",
		"HOME=/tmp; rm -rf /",
		"USER=$(whoami)",
		"SHELL=/bin/bash -c 'malicious'",
		
		// Variable substitution attacks
		"VAR=${PATH}/malicious",
		"VAR=$HOME/../../../etc/passwd",
		"VAR=%PATH%\\malicious",
		
		// Path traversal
		"CONFIG_PATH=../../../etc/passwd",
		"LOG_PATH=..\\..\\..\\windows\\system32",
		
		// Script injection
		"SCRIPT=#!/bin/bash\nrm -rf /",
		"COMMAND=<script>alert(1)</script>",
		
		// Unicode attacks
		"UNICОДE=value", // Cyrillic characters
		"VAR=vаlue", // Mixed scripts
		
		// Control characters
		"VAR=value\x00injected",
		"VAR=value\r\nINJECTED=evil",
		"VAR=value\nMALICIOUS=true",
		
		// Long values (DoS)
		"VAR=" + strings.Repeat("A", 100000),
		strings.Repeat("V", 10000) + "=value",
		
		// Valid env vars
		"PATH=/usr/bin:/bin",
		"HOME=/home/user",
		"USER=validuser",
		"",
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, envVar string) {
		// Test environment variable parsing
		key, value, err := parseEnvVar(envVar)
		if err != nil {
			return // Invalid format should be rejected
		}
		
		// Test key validation
		if !validateEnvVarKey(key) {
			return // Invalid keys should be rejected
		}
		
		// Test value validation
		isValidValue := validateEnvVarValue(value)
		_ = isValidValue
		
		// Test environment variable sanitization
		sanitizedKey := sanitizeEnvVarKey(key)
		sanitizedValue := sanitizeEnvVarValue(value)
		
		// Verify sanitization
		if strings.Contains(sanitizedKey, "\x00") || strings.Contains(sanitizedValue, "\x00") {
			t.Error("Sanitized env var contains null bytes")
		}
		
		// Test variable expansion safety
		expanded := expandEnvVarSafely(envVar)
		if containsCommandInjection(expanded) {
			t.Error("Environment variable expansion resulted in command injection")
		}
		
		// Test shell safety
		shellSafe := makeShellSafe(envVar)
		if !isShellSafe(shellSafe) {
			t.Error("Shell-safe transformation failed")
		}
	})
}

// FuzzTemplateProcessing tests template processing for injection attacks
func FuzzTemplateProcessing(f *testing.F) {
	seeds := []string{
		// Template injection attacks
		"{{.malicious}}",
		"{{range .evil}}{{.}}{{end}}",
		"{{with .dangerous}}{{.}}{{end}}",
		"{{template \"evil\" .}}",
		
		// Code execution attempts
		"{{.os.system \"rm -rf /\"}}",
		"{{exec \"malicious command\"}}",
		"{{eval \"dangerous code\"}}",
		
		// File access attempts
		"{{.file.read \"/etc/passwd\"}}",
		"{{include \"../../../etc/shadow\"}}",
		"{{template \"file:///etc/hosts\" .}}",
		
		// Variable injection
		"${malicious}",
		"%{runtime:command}",
		"#{dangerous}",
		"@{evil}",
		
		// Script tag injection
		"<script>alert(1)</script>",
		"javascript:alert(document.cookie)",
		"'><script>evil()</script>",
		
		// SQL injection in templates
		"'; DROP TABLE users; --",
		"' OR '1'='1",
		"UNION SELECT password FROM users",
		
		// Buffer overflow
		"{{" + strings.Repeat("A", 10000) + "}}",
		strings.Repeat("{{.field}}", 1000),
		
		// Valid templates
		"{{.username}}",
		"{{.config.value}}",
		"Hello {{.name}}!",
		"",
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, template string) {
		// Test template parsing
		parsed, err := parseTemplate(template)
		if err != nil {
			return // Invalid templates should be rejected
		}
		
		// Test template validation
		isValid := validateTemplate(parsed)
		_ = isValid
		
		// Test template sanitization
		sanitized := sanitizeTemplate(template)
		if containsScriptTags(sanitized) {
			t.Error("Sanitized template contains script tags")
		}
		
		// Test template execution safety
		result := executeTemplateSafely(template, getSampleData())
		if containsDangerousOutput(result) {
			t.Error("Template execution produced dangerous output")
		}
		
		// Test template function restrictions
		if containsRestrictedFunctions(template) {
			restricted := restrictTemplateFunctions(template)
			if stillContainsRestricted(restricted) {
				t.Error("Failed to restrict dangerous template functions")
			}
		}
	})
}

// FuzzConfigurationMerging tests configuration merging for injection
func FuzzConfigurationMerging(f *testing.F) {
	seeds := []string{
		// Prototype pollution attempts
		`{"__proto__": {"evil": true}}`,
		`{"constructor": {"prototype": {"malicious": true}}}`,
		
		// Key override attacks
		`{"admin": true, "admin": false}`,
		`{"config.override": "malicious"}`,
		
		// Path traversal in keys
		`{"../config": "value"}`,
		`{"config/../override": "evil"}`,
		
		// Deep nesting attacks (DoS)
		strings.Repeat(`{"nested":`, 1000) + `"value"` + strings.Repeat(`}`, 1000),
		
		// Valid configurations
		`{"normal": "config"}`,
		`{"nested": {"valid": "value"}}`,
		"",
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, configJSON string) {
		// Test configuration merging
		baseConfig := getBaseConfig()
		merged, err := mergeConfigurations(baseConfig, configJSON)
		if err != nil {
			return
		}
		
		// Validate merged configuration
		if hasPrototypePollutionConfig(merged) {
			t.Error("Configuration merge resulted in prototype pollution")
		}
		
		if hasUnauthorizedOverrides(merged) {
			t.Error("Configuration merge allowed unauthorized overrides")
		}
		
		// Test deep merge safety
		depth := calculateConfigDepth(merged)
		if depth > 50 {
			t.Error("Configuration merge created excessive nesting depth")
		}
	})
}

// Helper functions that should be implemented in the actual config package

func isJSONFormat(data string) bool {
	return strings.HasPrefix(strings.TrimSpace(data), "{") || strings.HasPrefix(strings.TrimSpace(data), "[")
}

func isYAMLFormat(data string) bool {
	return strings.Contains(data, ":") && !strings.Contains(data, "=")
}

func isTOMLFormat(data string) bool {
	return strings.Contains(data, "=") && !strings.Contains(data, ":")
}

func parseJSONConfig(_ string) (map[string]interface{}, error) {
	// TODO: Implement secure JSON parsing with size limits
	return nil, nil
}

func parseYAMLConfig(_ string) (map[string]interface{}, error) {
	// TODO: Implement secure YAML parsing without dangerous constructors
	return nil, nil
}

func parseTOMLConfig(_ string) (map[string]interface{}, error) {
	// TODO: Implement secure TOML parsing
	return nil, nil
}

func parseENVConfig(_ string) (map[string]interface{}, error) {
	// TODO: Implement secure ENV parsing
	return nil, nil
}

func validateConfigData(t *testing.T, config map[string]interface{}, format string) {
	// TODO: Implement configuration validation
	for key, value := range config {
		if containsDangerousPatternsConfig(key) {
			t.Errorf("%s config key contains dangerous pattern: %s", format, key)
		}
		if str, ok := value.(string); ok && containsDangerousPatternsConfig(str) {
			t.Errorf("%s config value contains dangerous pattern: %s", format, str)
		}
	}
}

func sanitizeConfigData(data string) string {
	// TODO: Implement configuration sanitization
	return strings.ReplaceAll(data, "\x00", "")
}

func validateConfigFormat(data string) bool {
	// TODO: Implement format validation
	return len(data) < 1000000 && utf8.ValidString(data)
}

func extractConfigKeys(_ string) []string {
	// TODO: Implement key extraction
	return []string{}
}

func containsDangerousPatternsConfig(input string) bool {
	dangerous := []string{
		"rm -rf", "$(", "`", "javascript:", "<script>",
		"'; DROP", "../", "..\\", "\x00",
	}
	lower := strings.ToLower(input)
	for _, pattern := range dangerous {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func parseEnvVar(envVar string) (string, string, error) {
	// TODO: Implement env var parsing
	parts := strings.SplitN(envVar, "=", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid format")
	}
	return parts[0], parts[1], nil
}

func validateEnvVarKey(key string) bool {
	// TODO: Implement env var key validation
	return len(key) > 0 && !strings.Contains(key, "\x00")
}

func validateEnvVarValue(value string) bool {
	// TODO: Implement env var value validation
	return !strings.Contains(value, "\x00")
}

func sanitizeEnvVarKey(key string) string {
	return strings.ReplaceAll(key, "\x00", "")
}

func sanitizeEnvVarValue(value string) string {
	return strings.ReplaceAll(value, "\x00", "")
}

func expandEnvVarSafely(envVar string) string {
	// TODO: Implement safe expansion
	return envVar
}

func containsCommandInjection(input string) bool {
	return containsDangerousPatternsConfig(input)
}

func makeShellSafe(input string) string {
	// TODO: Implement shell safety
	return input
}

func isShellSafe(input string) bool {
	return !containsCommandInjection(input)
}

func parseTemplate(_ string) (interface{}, error) {
	// TODO: Implement template parsing
	return nil, nil
}

func validateTemplate(_ interface{}) bool {
	// TODO: Implement template validation
	return true
}

func sanitizeTemplate(template string) string {
	// TODO: Implement template sanitization
	return template
}

func containsScriptTags(input string) bool {
	return strings.Contains(strings.ToLower(input), "<script>")
}

func executeTemplateSafely(_ string, _ interface{}) string {
	// TODO: Implement safe template execution
	return ""
}

func containsDangerousOutput(output string) bool {
	return containsDangerousPatternsConfig(output)
}

func getSampleData() interface{} {
	return map[string]string{"name": "test"}
}

func containsRestrictedFunctions(template string) bool {
	restricted := []string{"exec", "eval", "system", "file.read"}
	for _, fn := range restricted {
		if strings.Contains(template, fn) {
			return true
		}
	}
	return false
}

func restrictTemplateFunctions(template string) string {
	// TODO: Implement function restriction
	return template
}

func stillContainsRestricted(template string) bool {
	return containsRestrictedFunctions(template)
}

func getBaseConfig() map[string]interface{} {
	return map[string]interface{}{"base": "config"}
}

func mergeConfigurations(base map[string]interface{}, _ string) (map[string]interface{}, error) {
	// TODO: Implement secure configuration merging
	return base, nil
}

func hasPrototypePollutionConfig(config map[string]interface{}) bool {
	dangerous := []string{"__proto__", "constructor", "prototype"}
	for key := range config {
		for _, d := range dangerous {
			if strings.Contains(strings.ToLower(key), d) {
				return true
			}
		}
	}
	return false
}

func hasUnauthorizedOverrides(_ map[string]interface{}) bool {
	// TODO: Implement override detection
	return false
}

func calculateConfigDepth(_ map[string]interface{}) int {
	// TODO: Implement depth calculation
	return 1
}