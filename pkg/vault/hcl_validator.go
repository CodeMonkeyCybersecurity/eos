// pkg/vault/hcl_validator.go

package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"github.com/zclconf/go-cty/cty"
	"go.uber.org/zap"
)

// VaultPolicyValidator provides HCL validation for Vault policies
type VaultPolicyValidator struct {
	parser *hclparse.Parser
}

// PolicyValidationResult contains validation results and suggestions
type PolicyValidationResult struct {
	Valid       bool     `json:"valid"`
	Errors      []string `json:"errors,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
	ParsedBody  hcl.Body `json:"-"`
}

// NewVaultPolicyValidator creates a new HCL validator for Vault policies
func NewVaultPolicyValidator() *VaultPolicyValidator {
	return &VaultPolicyValidator{
		parser: hclparse.NewParser(),
	}
}

// ValidatePolicy validates a Vault policy HCL string
func (v *VaultPolicyValidator) ValidatePolicy(rc *eos_io.RuntimeContext, policyName, policyContent string) (*PolicyValidationResult, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔍 Validating Vault policy HCL", zap.String("policy", policyName))

	result := &PolicyValidationResult{
		Valid:       true,
		Errors:      []string{},
		Warnings:    []string{},
		Suggestions: []string{},
	}

	// Parse the HCL
	file, diags := v.parser.ParseHCL([]byte(policyContent), fmt.Sprintf("%s.hcl", policyName))
	if diags.HasErrors() {
		result.Valid = false
		for _, diag := range diags {
			result.Errors = append(result.Errors, diag.Error())
		}
		return result, nil
	}

	result.ParsedBody = file.Body

	// Perform Vault-specific policy validation
	if err := v.validateVaultPolicySemantics(rc, result, file.Body); err != nil {
		return nil, fmt.Errorf("semantic validation failed: %w", err)
	}

	if len(result.Errors) > 0 {
		result.Valid = false
	}

	log.Info(" Policy validation completed",
		zap.String("policy", policyName),
		zap.Bool("valid", result.Valid),
		zap.Int("errors", len(result.Errors)),
		zap.Int("warnings", len(result.Warnings)))

	return result, nil
}

// validateVaultPolicySemantics performs Vault-specific semantic validation
func (v *VaultPolicyValidator) validateVaultPolicySemantics(rc *eos_io.RuntimeContext, result *PolicyValidationResult, body hcl.Body) error {
	log := otelzap.Ctx(rc.Ctx)

	// Get the body content
	content, diags := body.Content(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{
				Type:       "path",
				LabelNames: []string{"path_pattern"},
			},
		},
	})

	if diags.HasErrors() {
		for _, diag := range diags {
			result.Errors = append(result.Errors, diag.Error())
		}
		return nil
	}

	// Validate each path block
	for _, block := range content.Blocks {
		if block.Type == "path" {
			if err := v.validatePathBlock(rc, result, block); err != nil {
				log.Warn("Path block validation failed", zap.Error(err))
			}
		}
	}

	return nil
}

// validatePathBlock validates a path block in a Vault policy
func (v *VaultPolicyValidator) validatePathBlock(rc *eos_io.RuntimeContext, result *PolicyValidationResult, block *hcl.Block) error {
	log := otelzap.Ctx(rc.Ctx)

	if len(block.Labels) == 0 {
		result.Errors = append(result.Errors, "path block missing path pattern")
		return nil
	}

	pathPattern := block.Labels[0]
	log.Debug("Validating path block", zap.String("path", pathPattern))

	// Define valid attributes for path blocks
	validAttributes := map[string]bool{
		"capabilities":        true,
		"denied_parameters":   true,
		"required_parameters": true,
		"allowed_parameters":  true,
		"control_group":       true,
		"mfa_methods":         true,
		"min_wrapping_ttl":    true,
		"max_wrapping_ttl":    true,
	}

	// Invalid attributes that users might mistakenly use
	invalidAttributes := map[string]string{
		"max_ttl":     "max_ttl is not valid in Vault ACL policies. Use token policies or auth method configuration instead.",
		"ttl":         "ttl is not valid in Vault ACL policies. Use token policies or auth method configuration instead.",
		"default_ttl": "default_ttl is not valid in Vault ACL policies. Use token policies or auth method configuration instead.",
		"period":      "period is not valid in Vault ACL policies. Use token policies or auth method configuration instead.",
	}

	// Common syntax mistakes
	parameterValidation := map[string]string{
		"denied_parameters":   "must be an object/map, not a list",
		"allowed_parameters":  "must be an object/map, not a list",
		"required_parameters": "can be either a list or object/map",
	}

	// Get block content
	content, diags := block.Body.Content(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{
			{Name: "capabilities", Required: false},
			{Name: "denied_parameters", Required: false},
			{Name: "required_parameters", Required: false},
			{Name: "allowed_parameters", Required: false},
			{Name: "control_group", Required: false},
			{Name: "mfa_methods", Required: false},
			{Name: "min_wrapping_ttl", Required: false},
			{Name: "max_wrapping_ttl", Required: false},
			// Include invalid ones to catch them
			{Name: "max_ttl", Required: false},
			{Name: "ttl", Required: false},
			{Name: "default_ttl", Required: false},
			{Name: "period", Required: false},
		},
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "control_group"},
		},
	})

	if diags.HasErrors() {
		for _, diag := range diags {
			result.Errors = append(result.Errors, fmt.Sprintf("path %s: %s", pathPattern, diag.Error()))
		}
	}

	// Check for invalid attributes
	for name, attr := range content.Attributes {
		if suggestion, isInvalid := invalidAttributes[name]; isInvalid {
			result.Errors = append(result.Errors,
				fmt.Sprintf("path %s: invalid attribute '%s' - %s", pathPattern, name, suggestion))
		} else if !validAttributes[name] {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("path %s: unknown attribute '%s'", pathPattern, name))
		}

		// Check parameter syntax
		if syntax, needsValidation := parameterValidation[name]; needsValidation {
			if err := v.validateParameterSyntax(result, pathPattern, name, attr, syntax); err != nil {
				log.Debug("Parameter syntax validation failed", zap.Error(err))
			}
		}
	}

	// Validate capabilities if present
	if capAttr, exists := content.Attributes["capabilities"]; exists {
		if err := v.validateCapabilities(result, pathPattern, capAttr); err != nil {
			log.Warn("Capabilities validation failed", zap.Error(err))
		}
	}

	// Check for common path pattern issues
	v.validatePathPattern(result, pathPattern)

	return nil
}

// validateParameterSyntax validates parameter attribute syntax
func (v *VaultPolicyValidator) validateParameterSyntax(result *PolicyValidationResult, pathPattern, attrName string, attr *hcl.Attribute, expectedSyntax string) error {
	// Try to evaluate the attribute
	val, diags := attr.Expr.Value(nil)
	if diags.HasErrors() {
		return nil // Skip if we can't evaluate
	}

	// Check for common mistakes based on attribute type
	switch attrName {
	case "denied_parameters", "allowed_parameters":
		// These must be objects/maps, not lists
		if val.Type().IsListType() || val.Type().IsTupleType() {
			result.Errors = append(result.Errors,
				fmt.Sprintf("path %s: %s %s", pathPattern, attrName, expectedSyntax))
		}
	case "required_parameters":
		// This can be either list or object, so less strict
		if !val.Type().IsListType() && !val.Type().IsTupleType() && !val.Type().IsObjectType() && !val.Type().IsMapType() {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("path %s: %s should be a list or object", pathPattern, attrName))
		}
	}

	return nil
}

// validateCapabilities validates the capabilities list
func (v *VaultPolicyValidator) validateCapabilities(result *PolicyValidationResult, pathPattern string, capAttr *hcl.Attribute) error {
	validCapabilities := map[string]bool{
		"create": true,
		"read":   true,
		"update": true,
		"delete": true,
		"list":   true,
		"sudo":   true,
		"deny":   true,
		"patch":  true,
	}

	// Try to evaluate the attribute as a list
	val, diags := capAttr.Expr.Value(nil)
	if diags.HasErrors() {
		return nil // Skip if we can't evaluate
	}

	if val.Type().IsListType() || val.Type().IsTupleType() {
		for it := val.ElementIterator(); it.Next(); {
			_, capVal := it.Element()
			if capVal.Type() == cty.String {
				capability := capVal.AsString()
				if !validCapabilities[capability] {
					result.Errors = append(result.Errors,
						fmt.Sprintf("path %s: invalid capability '%s'", pathPattern, capability))
				}
			}
		}
	}

	return nil
}

// validatePathPattern validates common path pattern issues
func (v *VaultPolicyValidator) validatePathPattern(result *PolicyValidationResult, pathPattern string) {
	// Check for common templating issues
	if strings.Contains(pathPattern, "{{") && strings.Contains(pathPattern, "}}") {
		// Check for proper identity templating
		if strings.Contains(pathPattern, "{{identity.entity.name}}") {
			result.Suggestions = append(result.Suggestions,
				fmt.Sprintf("path %s: using identity templating - ensure entities are properly configured", pathPattern))
		}

		// Check for malformed templating
		if strings.Count(pathPattern, "{{") != strings.Count(pathPattern, "}}") {
			result.Errors = append(result.Errors,
				fmt.Sprintf("path %s: malformed template syntax - mismatched braces", pathPattern))
		}
	}

	// Check for overly broad permissions
	if pathPattern == "*" {
		result.Warnings = append(result.Warnings,
			"path '*': extremely broad permissions - consider more specific paths")
	}

	// Check for secret engine specific patterns
	if strings.HasPrefix(pathPattern, "secret/data/") {
		result.Suggestions = append(result.Suggestions,
			fmt.Sprintf("path %s: using KV v2 engine - ensure corresponding metadata path is also configured", pathPattern))
	}
}

// ValidatePolicyString is a convenience function for validating policy strings
func ValidatePolicyString(rc *eos_io.RuntimeContext, policyName, policyContent string) error {
	validator := NewVaultPolicyValidator()
	result, err := validator.ValidatePolicy(rc, policyName, policyContent)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if !result.Valid {
		return fmt.Errorf("policy validation failed: %s", strings.Join(result.Errors, "; "))
	}

	// Log warnings and suggestions
	log := otelzap.Ctx(rc.Ctx)
	for _, warning := range result.Warnings {
		log.Warn("Policy validation warning", zap.String("warning", warning))
	}
	for _, suggestion := range result.Suggestions {
		log.Info("Policy validation suggestion", zap.String("suggestion", suggestion))
	}

	return nil
}

// ValidateAndFixCommonIssues attempts to automatically fix common policy issues
func ValidateAndFixCommonIssues(rc *eos_io.RuntimeContext, policyName, policyContent string) (string, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Attempting to fix common policy issues", zap.String("policy", policyName))

	// Fix common invalid attributes by removing them
	fixedContent := policyContent

	// Remove max_ttl from path blocks (not valid in ACL policies)
	fixedContent = removeInvalidPathAttributes(fixedContent, []string{"max_ttl", "ttl", "default_ttl", "period"})

	// Fix denied_parameters syntax (convert from list to object)
	fixedContent = fixParameterSyntax(fixedContent)

	// Validate the fixed content
	if err := ValidatePolicyString(rc, policyName, fixedContent); err != nil {
		return fixedContent, fmt.Errorf("fixed policy still invalid: %w", err)
	}

	if fixedContent != policyContent {
		log.Info(" Policy automatically fixed",
			zap.String("policy", policyName),
			zap.Int("original_length", len(policyContent)),
			zap.Int("fixed_length", len(fixedContent)))
	}

	return fixedContent, nil
}

// removeInvalidPathAttributes removes invalid attributes from path blocks
func removeInvalidPathAttributes(content string, invalidAttrs []string) string {
	lines := strings.Split(content, "\n")
	var result []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		shouldRemove := false

		for _, attr := range invalidAttrs {
			if strings.HasPrefix(trimmed, attr+" ") || strings.HasPrefix(trimmed, attr+"=") {
				shouldRemove = true
				break
			}
		}

		if !shouldRemove {
			result = append(result, line)
		}
	}

	return strings.Join(result, "\n")
}

// fixParameterSyntax converts list-style parameter definitions to object-style
func fixParameterSyntax(content string) string {
	lines := strings.Split(content, "\n")
	var result []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Look for denied_parameters or allowed_parameters as lists
		if strings.Contains(trimmed, "denied_parameters =") && strings.Contains(trimmed, "[") {
			// Convert list to object format
			if strings.Contains(trimmed, "=") {
				parts := strings.Split(trimmed, "=")
				if len(parts) == 2 {
					prefix := strings.TrimSpace(parts[0])
					listPart := strings.TrimSpace(parts[1])

					// Extract list items
					listPart = strings.Trim(listPart, "[]")
					items := strings.Split(listPart, ",")

					// Convert to object format
					indent := strings.Repeat(" ", len(line)-len(strings.TrimLeft(line, " ")))
					result = append(result, fmt.Sprintf("%s%s = {", indent, prefix))

					for _, item := range items {
						item = strings.TrimSpace(item)
						item = strings.Trim(item, "\"")
						if item != "" {
							result = append(result, fmt.Sprintf("%s  \"%s\" = []", indent, item))
						}
					}
					result = append(result, fmt.Sprintf("%s}", indent))
					continue
				}
			}
		}

		result = append(result, line)
	}

	return strings.Join(result, "\n")
}
