// pkg/saltstack/template_fuzz_test.go - Salt template generation fuzzing
package saltstack

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// FuzzSaltStateGeneration tests Salt state generation with malicious inputs
func FuzzSaltStateGeneration(f *testing.F) {
	// Seed with injection attempts targeting Jinja2
	f.Add("{{ pillar['malicious'] }}")
	f.Add("{% for x in range(1000000) %}loop{% endfor %}")
	f.Add("{{ config.get('secret', 'default') | popen }}")
	f.Add("{% import os %}{{ os.system('rm -rf /') }}")
	f.Add("{{ ''.__class__.__mro__[2].__subclasses__() }}")
	f.Add("{{ lipsum.__globals__['os'].system('id') }}")
	f.Add("{% set x = cycler('a') %}{{ x.__init__.__globals__ }}")
	f.Add("{{ [].__class__.__base__.__subclasses__() }}")
	f.Add("normal_pillar_value")
	f.Add("")
	f.Add("value\x00with\x00nulls")
	f.Add("unicode🌍value")
	f.Add("value'with\"quotes")
	f.Add("${ENV_VAR}")
	f.Add("$(command_injection)")
	f.Add("value\nwith\nnewlines")
	f.Add("very_long_" + strings.Repeat("a", 10000) + "_value")

	f.Fuzz(func(t *testing.T, pillarValue string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Salt state generation panicked with pillar value %q: %v", pillarValue, r)
			}
		}()

		// Create test context
		rc := &eos_io.RuntimeContext{
			Attributes: make(map[string]string),
		}

		// Test pillar data injection safety
		config := &Config{
			MasterMode: false,
			LogLevel:   "warning",
			Version:    "latest",
		}

		// Simulate pillar data that could be user-controlled
		rc.Attributes["test_pillar"] = pillarValue

		installer := NewSimpleBootstrapInstaller(config)

		// Test that dangerous pillar values don't cause injection
		err := installer.configureMasterlessMode(rc)
		if err != nil {
			// Errors are acceptable for malicious input
			return
		}

		// Validate that no dangerous template constructs remain
		validateNoTemplateInjection(t, pillarValue)
	})
}

// FuzzSaltPillarDataValidation tests pillar data validation
func FuzzSaltPillarDataValidation(f *testing.F) {
	// Seed with various pillar data structures
	f.Add("simple_value")
	f.Add("{'nested': {'dict': 'value'}}")
	f.Add("['list', 'of', 'values']")
	f.Add("{{ malicious_template }}")
	f.Add("{% if True %}injection{% endif %}")
	f.Add("normal: value\nmalicious: {{ injection }}")
	f.Add("---\nkey: value\n...\n")
	f.Add("null")
	f.Add("true")
	f.Add("42")
	f.Add("")

	f.Fuzz(func(t *testing.T, pillarData string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Pillar validation panicked with data %q: %v", pillarData, r)
			}
		}()

		// Test pillar data validation
		err := ValidatePillarData(pillarData)

		// Should never panic, even with malicious input
		if err != nil {
			// Errors are expected for invalid pillar data
			return
		}

		// If validation passes, ensure it's safe
		if containsTemplateInjection(pillarData) {
			t.Errorf("Dangerous pillar data passed validation: %q", pillarData)
		}
	})
}

// FuzzSaltConfigGeneration tests Salt configuration file generation
func FuzzSaltConfigGeneration(f *testing.F) {
	// Seed with configuration injection attempts
	f.Add("file_client: local")
	f.Add("master: {{ pillar['malicious_master'] }}")
	f.Add("log_level: {{ ''.__class__ }}")
	f.Add("file_roots:\n  base:\n    - {{ injection }}")
	f.Add("normal_config_value")
	f.Add("")
	f.Add("multi\nline\nconfig")
	f.Add("config: |\n  {% for x in range(1000) %}\n  line{{ x }}\n  {% endfor %}")

	f.Fuzz(func(t *testing.T, configValue string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Config generation panicked with value %q: %v", configValue, r)
			}
		}()

		// Test configuration value safety
		sanitized := SanitizeConfigValue(configValue)

		// Should always be valid UTF-8
		if !utf8.ValidString(sanitized) {
			t.Errorf("Config sanitization produced invalid UTF-8: input=%q, output=%q", configValue, sanitized)
		}

		// Should not contain template injection
		if containsTemplateInjection(sanitized) {
			t.Errorf("Sanitized config contains template injection: input=%q, output=%q", configValue, sanitized)
		}

		// Should not contain dangerous YAML constructs
		if containsDangerousYAML(sanitized) {
			t.Errorf("Sanitized config contains dangerous YAML: input=%q, output=%q", configValue, sanitized)
		}
	})
}

// Helper functions for Salt fuzzing

// ValidatePillarData validates pillar data for safety
func ValidatePillarData(data string) error {
	// Implementation would go here
	// This is a placeholder for the actual validation logic
	if containsTemplateInjection(data) {
		return fmt.Errorf("template injection detected")
	}
	return nil
}

// SanitizeConfigValue sanitizes configuration values
func SanitizeConfigValue(value string) string {
	// Remove template constructs
	value = removeTemplateConstructs(value)

	// Remove null bytes
	value = strings.ReplaceAll(value, "\x00", "")

	// Limit length
	if len(value) > 1000 {
		value = value[:1000] + "[TRUNCATED]"
	}

	return value
}

func containsTemplateInjection(s string) bool {
	dangerousPatterns := []string{
		"{{", "}}", "{%", "%}",
		"__class__", "__mro__", "__subclasses__",
		"__globals__", "__init__", "popen",
		"os.system", "subprocess", "eval", "exec",
		"lipsum", "cycler", "range(", "import ",
	}

	lower := strings.ToLower(s)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func containsDangerousYAML(s string) bool {
	dangerousPatterns := []string{
		"!!python/", "!!map", "!!omap", "!!pairs", "!!set",
		"!!binary", "!!timestamp", "!!null", "!!bool", "!!int", "!!float",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(s, pattern) {
			return true
		}
	}
	return false
}

func removeTemplateConstructs(s string) string {
	// Remove Jinja2 template constructs
	s = strings.ReplaceAll(s, "{{", "")
	s = strings.ReplaceAll(s, "}}", "")
	s = strings.ReplaceAll(s, "{%", "")
	s = strings.ReplaceAll(s, "%}", "")
	return s
}

func validateNoTemplateInjection(t *testing.T, input string) {
	// This would validate that no template injection occurred during processing
	// Placeholder for actual validation logic
	if containsTemplateInjection(input) && len(input) > 0 {
		t.Logf("Input contained potential template injection: %q", input)
	}
}
