// pkg/vault/policy_builder.go

package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"github.com/zclconf/go-cty/cty"
	"go.uber.org/zap"
)

// PolicyBuilder provides a type-safe way to build Vault policies programmatically
type PolicyBuilder struct {
	file  *hclwrite.File
	body  *hclwrite.Body
	paths []*PolicyPath
}

// PolicyPath represents a single path block in a Vault policy
type PolicyPath struct {
	Pattern            string
	Capabilities       []string
	DeniedParameters   map[string][]string
	AllowedParameters  map[string][]string
	RequiredParameters []string
	MFAMethods         []string
	MinWrappingTTL     string
	MaxWrappingTTL     string
	ControlGroup       *ControlGroup
}

// ControlGroup represents control group configuration
type ControlGroup struct {
	MaxTTL  string
	Factors []ControlGroupFactor
}

// ControlGroupFactor represents a factor in control group authorization
type ControlGroupFactor struct {
	Name       string
	GroupNames []string
	Approvals  int
}

// NewPolicyBuilder creates a new Vault policy builder
func NewPolicyBuilder() *PolicyBuilder {
	file := hclwrite.NewEmptyFile()

	return &PolicyBuilder{
		file:  file,
		body:  file.Body(),
		paths: make([]*PolicyPath, 0),
	}
}

// AddPath adds a new path to the policy with basic capabilities
func (pb *PolicyBuilder) AddPath(pattern string, capabilities ...string) *PolicyBuilder {
	path := &PolicyPath{
		Pattern:      pattern,
		Capabilities: capabilities,
	}
	pb.paths = append(pb.paths, path)
	return pb
}

// AddPathWithDeniedParams adds a path with denied parameters
func (pb *PolicyBuilder) AddPathWithDeniedParams(pattern string, capabilities []string, deniedParams map[string][]string) *PolicyBuilder {
	path := &PolicyPath{
		Pattern:          pattern,
		Capabilities:     capabilities,
		DeniedParameters: deniedParams,
	}
	pb.paths = append(pb.paths, path)
	return pb
}

// AddPathWithRequiredParams adds a path with required parameters
func (pb *PolicyBuilder) AddPathWithRequiredParams(pattern string, capabilities []string, requiredParams []string) *PolicyBuilder {
	path := &PolicyPath{
		Pattern:            pattern,
		Capabilities:       capabilities,
		RequiredParameters: requiredParams,
	}
	pb.paths = append(pb.paths, path)
	return pb
}

// AddComment adds a comment to the policy
func (pb *PolicyBuilder) AddComment(comment string) *PolicyBuilder {
	// Add comment as a standalone comment
	pb.body.AppendNewline()
	tokens := hclwrite.Tokens{
		{Type: hclsyntax.TokenComment, Bytes: []byte(fmt.Sprintf("# %s", comment))},
		{Type: hclsyntax.TokenNewline, Bytes: []byte("\n")},
	}
	pb.body.AppendUnstructuredTokens(tokens)
	return pb
}

// AddSection adds a section header comment
func (pb *PolicyBuilder) AddSection(title string) *PolicyBuilder {
	pb.body.AppendNewline()
	pb.AddComment(strings.Repeat("=", 50))
	pb.AddComment(title)
	pb.AddComment(strings.Repeat("=", 50))
	return pb
}

// Build generates the final HCL policy string
func (pb *PolicyBuilder) Build(rc *eos_io.RuntimeContext) (string, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Building Vault policy programmatically", zap.Int("paths", len(pb.paths)))

	// Add all paths to the HCL body
	for _, path := range pb.paths {
		if err := pb.addPathToBody(path); err != nil {
			return "", fmt.Errorf("failed to add path %s: %w", path.Pattern, err)
		}
	}

	// Generate the HCL content
	content := string(pb.file.Bytes())

	log.Info(" Policy built successfully",
		zap.Int("paths", len(pb.paths)),
		zap.Int("size", len(content)))

	return content, nil
}

// addPathToBody adds a PolicyPath to the HCL body
func (pb *PolicyBuilder) addPathToBody(path *PolicyPath) error {
	// Create path block
	pathBlock := pb.body.AppendNewBlock("path", []string{path.Pattern})
	pathBody := pathBlock.Body()

	// Add capabilities
	if len(path.Capabilities) > 0 {
		capValues := make([]cty.Value, len(path.Capabilities))
		for i, cap := range path.Capabilities {
			capValues[i] = cty.StringVal(cap)
		}
		pathBody.SetAttributeValue("capabilities", cty.ListVal(capValues))
	}

	// Add denied parameters
	if len(path.DeniedParameters) > 0 {
		deniedMap := make(map[string]cty.Value)
		for param, values := range path.DeniedParameters {
			if len(values) == 0 {
				deniedMap[param] = cty.ListValEmpty(cty.String)
			} else {
				ctValues := make([]cty.Value, len(values))
				for i, v := range values {
					ctValues[i] = cty.StringVal(v)
				}
				deniedMap[param] = cty.ListVal(ctValues)
			}
		}
		pathBody.SetAttributeValue("denied_parameters", cty.ObjectVal(deniedMap))
	}

	// Add allowed parameters
	if len(path.AllowedParameters) > 0 {
		allowedMap := make(map[string]cty.Value)
		for param, values := range path.AllowedParameters {
			if len(values) == 0 {
				allowedMap[param] = cty.ListValEmpty(cty.String)
			} else {
				ctValues := make([]cty.Value, len(values))
				for i, v := range values {
					ctValues[i] = cty.StringVal(v)
				}
				allowedMap[param] = cty.ListVal(ctValues)
			}
		}
		pathBody.SetAttributeValue("allowed_parameters", cty.ObjectVal(allowedMap))
	}

	// Add required parameters
	if len(path.RequiredParameters) > 0 {
		reqValues := make([]cty.Value, len(path.RequiredParameters))
		for i, param := range path.RequiredParameters {
			reqValues[i] = cty.StringVal(param)
		}
		pathBody.SetAttributeValue("required_parameters", cty.ListVal(reqValues))
	}

	// Add MFA methods
	if len(path.MFAMethods) > 0 {
		mfaValues := make([]cty.Value, len(path.MFAMethods))
		for i, method := range path.MFAMethods {
			mfaValues[i] = cty.StringVal(method)
		}
		pathBody.SetAttributeValue("mfa_methods", cty.ListVal(mfaValues))
	}

	// Add wrapping TTLs
	if path.MinWrappingTTL != "" {
		pathBody.SetAttributeValue("min_wrapping_ttl", cty.StringVal(path.MinWrappingTTL))
	}
	if path.MaxWrappingTTL != "" {
		pathBody.SetAttributeValue("max_wrapping_ttl", cty.StringVal(path.MaxWrappingTTL))
	}

	// Add control group (if needed in the future)
	// Control groups require careful implementation due to their complexity
	// For now, we'll skip them to avoid the parsing issues we encountered
	_ = path.ControlGroup // acknowledge we're not using this field yet

	return nil
}

// Predefined builder methods for common patterns

// AddTokenCapabilities adds standard token management capabilities
func (pb *PolicyBuilder) AddTokenCapabilities() *PolicyBuilder {
	pb.AddSection("Token and Identity Management")
	pb.AddPath("auth/token/lookup-self", "read")
	pb.AddPath("auth/token/renew-self", "update")
	pb.AddPath("auth/token/revoke-self", "update")
	pb.AddPath("sys/capabilities-self", "update")
	return pb
}

// AddIdentityCapabilities adds identity-related capabilities with templating
func (pb *PolicyBuilder) AddIdentityCapabilities() *PolicyBuilder {
	pb.AddPath("identity/entity/id/{{identity.entity.id}}", "read")
	pb.AddPath("identity/entity/name/{{identity.entity.name}}", "read")
	return pb
}

// AddCubbyholeAccess adds personal cubbyhole access
func (pb *PolicyBuilder) AddCubbyholeAccess() *PolicyBuilder {
	pb.AddSection("Personal Cubbyhole Access")
	pb.AddPath("cubbyhole/*", "create", "read", "update", "delete", "list")
	pb.AddPath("sys/wrapping/wrap", "update")
	pb.AddPath("sys/wrapping/lookup", "update")
	pb.AddPath("sys/wrapping/unwrap", "update")
	return pb
}

// AddUserSecrets adds user-specific secret access with templating
func (pb *PolicyBuilder) AddUserSecrets() *PolicyBuilder {
	pb.AddSection("User-Specific Secrets")
	pb.AddPathWithRequiredParams(
		"secret/data/eos/{{identity.entity.name}}/*",
		[]string{"create", "read", "update", "delete", "list"},
		[]string{"version"},
	)
	pb.AddPath("secret/metadata/eos/{{identity.entity.name}}/*", "read", "list", "delete")
	return pb
}

// AddSharedSecretsReadOnly adds read-only access to shared secrets
func (pb *PolicyBuilder) AddSharedSecretsReadOnly() *PolicyBuilder {
	pb.AddSection("Shared Secrets (Read-Only)")
	pb.AddPath("secret/data/shared/*", "read", "list")
	return pb
}

// AddServiceSecrets adds full access to service secrets
// RATIONALE: Services deployed by Eos need to store their secrets (API keys, passwords, etc.)
// SECURITY: Scoped to secret/data/services/* - cannot access user or shared secrets
// THREAT MODEL: Prevents privilege escalation - services can't read other users' secrets
func (pb *PolicyBuilder) AddServiceSecrets() *PolicyBuilder {
	pb.AddSection("Service Secrets (Full Access)")
	pb.AddComment("Services deployed by Eos store their secrets here")
	pb.AddPath("secret/data/services/*", "create", "read", "update", "delete", "list")
	pb.AddPath("secret/metadata/services/*", "read", "list", "delete")
	return pb
}

// AddConsulIntegrationSecrets adds access to Consul integration metadata storage
// RATIONALE: Consul-Vault integration requires storing bootstrap tokens and management tokens
// SECURITY: Scoped to services/{env}/consul/* paths - environment-isolated secrets
// THREAT MODEL: Prevents privilege escalation - users can't access other environment secrets
//
// PATHS: secret/data/services/{environment}/consul/* (production, staging, development, review)
//
// Each environment has isolated Consul secrets:
//   - secret/data/services/production/consul/bootstrap-token
//   - secret/data/services/production/consul/management-token
//   - secret/data/services/development/consul/bootstrap-token
//   - etc.
func (pb *PolicyBuilder) AddConsulIntegrationSecrets() *PolicyBuilder {
	pb.AddSection("Consul Integration Secrets")
	pb.AddComment("Store Consul bootstrap tokens and metadata for service integration")

	// Environment-aware paths (legacy paths removed - data migrated to new structure)
	pb.AddPath("secret/data/services/*/consul/*", "create", "read", "update", "delete", "list")
	pb.AddPath("secret/metadata/services/*/consul/*", "read", "list", "delete")

	return pb
}

// AddSecretsEngineManagement adds limited secrets engine management capabilities
// RATIONALE: Eos needs to enable secrets engines for service integrations (Consul, DB, PKI)
// SECURITY: Scoped to specific mount paths - cannot disable core KV engine or create arbitrary engines
// THREAT MODEL: Prevents accidental/malicious destruction of core secrets infrastructure
func (pb *PolicyBuilder) AddSecretsEngineManagement() *PolicyBuilder {
	pb.AddSection("Secrets Engine Management (Limited)")
	pb.AddComment("Allow Eos to integrate services with Vault secrets engines")
	pb.AddPath("sys/mounts", "read", "list")
	pb.AddPath("sys/mounts/consul", "create", "read", "update")
	pb.AddPath("sys/mounts/database", "create", "read", "update")
	pb.AddPath("sys/mounts/pki", "create", "read", "update")
	return pb
}

// AddConsulSecretsEngine adds full access to Consul secrets engine
// RATIONALE: Configure Consul secrets engine for dynamic token generation
// SECURITY: Only accessible after secrets engine is enabled, tokens are time-limited (1h-24h TTL)
// THREAT MODEL: Consul ACL policies still enforced on generated tokens - Vault doesn't bypass Consul security
func (pb *PolicyBuilder) AddConsulSecretsEngine() *PolicyBuilder {
	pb.AddSection("Consul Secrets Engine (Full Access)")
	pb.AddComment("Configure and use Consul secrets engine for dynamic token generation")
	pb.AddPath("consul/*", "create", "read", "update", "delete", "list")
	return pb
}

// AddSelfServiceUserpass adds self-service userpass management with restrictions
func (pb *PolicyBuilder) AddSelfServiceUserpass() *PolicyBuilder {
	pb.AddSection("Self-Service User Management")
	deniedParams := map[string][]string{
		"policies":       {},
		"token_policies": {},
		"token_ttl":      {},
		"token_max_ttl":  {},
	}
	pb.AddPathWithDeniedParams(
		"auth/userpass/users/{{identity.entity.name}}",
		[]string{"read", "update"},
		deniedParams,
	)
	return pb
}

// AddMFAManagement adds MFA management capabilities
func (pb *PolicyBuilder) AddMFAManagement() *PolicyBuilder {
	pb.AddSection("MFA Management")
	pb.AddPath("auth/totp/keys/{{identity.entity.name}}", "create", "read", "update", "delete")
	pb.AddPath("auth/totp/code/{{identity.entity.name}}", "update")
	return pb
}

// AddSecurityDenials adds explicit denials for dangerous operations
func (pb *PolicyBuilder) AddSecurityDenials() *PolicyBuilder {
	pb.AddSection("Security Denials")
	dangerousPaths := []string{
		"sys/raw/*",
		"sys/unseal",
		"sys/seal",
		"sys/step-down",
		"sys/rekey/*",
		"auth/token/create-orphan",
		"auth/token/create/*",
		"sys/auth/*",
		"sys/mounts/*",
		"sys/policy/*",
	}

	for _, path := range dangerousPaths {
		pb.AddPath(path, "deny")
	}
	return pb
}
