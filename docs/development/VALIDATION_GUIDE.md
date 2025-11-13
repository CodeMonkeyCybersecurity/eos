# Vault HCL Policy Validation

*Last Updated: 2025-01-14*

This module provides comprehensive HCL validation for HashiCorp Vault policies to prevent parsing errors and ensure best practices.

## Problem Solved

During `eos enable vault`, policies are written to Vault's ACL system. Vault has specific syntax requirements and limitations that aren't immediately obvious. The most common issues include:

1. **Invalid Path Attributes**: Using `max_ttl`, `ttl`, `default_ttl`, `period` at the path level (these belong in token policies, not ACL policies)
2. **Malformed Template Syntax**: Incorrect identity templating with `{{identity.entity.name}}`
3. **Invalid Capabilities**: Typos in capability names like `"reed"` instead of `"read"`
4. **Overly Broad Permissions**: Using wildcard paths without consideration

## Implementation

### Core Components

#### `VaultPolicyValidator`
Main validation struct that uses HashiCorp's HCL v2 parser:
```go
validator := NewVaultPolicyValidator()
result, err := validator.ValidatePolicy(rc, "policy-name", policyContent)
```

#### `PolicyValidationResult`
Contains comprehensive validation feedback:
```go
type PolicyValidationResult struct {
    Valid       bool     // Whether policy is syntactically and semantically valid
    Errors      []string // Blocking errors that prevent policy use
    Warnings    []string // Non-blocking issues that should be addressed
    Suggestions []string // Best practice recommendations
}
```

#### Automatic Issue Resolution
```go
fixedPolicy, err := ValidateAndFixCommonIssues(rc, policyName, originalPolicy)
```

### Validation Phases

1. **Syntax Validation**: Uses HCL v2 parser to ensure valid HCL syntax
2. **Semantic Validation**: Checks Vault-specific policy rules and constraints
3. **Best Practice Analysis**: Suggests improvements for security and maintainability
4. **Automatic Fixes**: Removes known invalid attributes and corrects common mistakes

### Integration Points

The validator is automatically called during policy writing in `phase11_write_policies.go`:

```go
// Validate and fix common HCL issues
fixedPolicy, err := ValidateAndFixCommonIssues(rc, policy.name, pol)
if err != nil {
    // Log warning but continue with original policy
    log.Warn("Policy validation failed, using original", zap.Error(err))
} else if fixedPolicy != pol {
    // Use the fixed version
    log.Info("Policy automatically fixed", zap.String("policy", policy.name))
    pol = fixedPolicy
}
```

## Validation Rules

### Path Block Attributes

**Valid Attributes:**
- `capabilities` - List of operations: create, read, update, delete, list, sudo, deny, patch
- `denied_parameters` - Parameters to explicitly deny
- `required_parameters` - Parameters that must be present
- `allowed_parameters` - Parameters that are allowed
- `control_group` - Control group configuration for approval workflows
- `mfa_methods` - MFA requirements for path access
- `min_wrapping_ttl`, `max_wrapping_ttl` - Response wrapping TTLs

**Invalid Attributes (Automatically Removed):**
- `max_ttl` - Not valid in ACL policies, belongs in token policies
- `ttl` - Not valid in ACL policies, belongs in token policies  
- `default_ttl` - Not valid in ACL policies, belongs in token policies
- `period` - Not valid in ACL policies, belongs in token policies

### Common Fixes Applied

1. **Remove Invalid TTL Attributes**: Strips `max_ttl`, `ttl`, etc. from path blocks
2. **Template Validation**: Ensures `{{identity.entity.name}}` syntax is correct
3. **Capability Validation**: Checks for valid capability names
4. **Path Pattern Analysis**: Warns about overly broad permissions

## Error Examples

### Before Fix (Invalid Policy)
```hcl
path "secret/data/eos/{{identity.entity.name}}/*" { 
  capabilities = ["create", "read", "update", "delete", "list"]
  max_ttl = "24h"  #  Invalid in ACL policies
  required_parameters = ["version"]
}
```

### After Fix (Valid Policy)
```hcl
path "secret/data/eos/{{identity.entity.name}}/*" { 
  capabilities = ["create", "read", "update", "delete", "list"]
  required_parameters = ["version"]
}
```

## Error Resolution

The specific parsing error encountered:
```
failed to parse policy: 1 error occurred:
* path "secret/data/eos/{{identity.entity.name}}/*": invalid key "max_ttl" on line 31
```

Was resolved by:
1. **Identifying the Issue**: `max_ttl` is not valid in Vault ACL policies
2. **Creating Validation Logic**: Added HCL parser to catch such issues
3. **Implementing Auto-Fix**: Automatically removes invalid attributes
4. **Adding Prevention**: Future policies are validated before submission

## Usage in Development

### Manual Validation
```go
// Validate a policy string
err := ValidatePolicyString(rc, "my-policy", policyContent)
if err != nil {
    log.Error("Policy validation failed", zap.Error(err))
}
```

### Validation with Auto-Fix
```go
// Validate and automatically fix common issues
fixedPolicy, err := ValidateAndFixCommonIssues(rc, "my-policy", policyContent)
if err != nil {
    return fmt.Errorf("policy validation failed: %w", err)
}
```

### Custom Validation
```go
validator := NewVaultPolicyValidator()
result, err := validator.ValidatePolicy(rc, "my-policy", policyContent)
if err != nil {
    return err
}

// Handle validation results
for _, error := range result.Errors {
    log.Error("Validation error", zap.String("error", error))
}
for _, warning := range result.Warnings {
    log.Warn("Validation warning", zap.String("warning", warning))
}
```

## Dependencies

- `github.com/hashicorp/hcl/v2` - Official HCL v2 parser from HashiCorp
- `github.com/zclconf/go-cty` - Type system used by HCL v2

This ensures we use the same parsing logic as HashiCorp Vault itself, providing accurate validation results.