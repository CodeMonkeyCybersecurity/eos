# pkg/vault Consolidation Plan v2 (Revised)

*Last Updated: 2025-10-14*
*Revision: Incorporates adversarial feedback and focuses on proven pain points*

## Executive Summary

**Philosophy Change:**
~~"Consolidate all duplication"~~
 **"Fix what actually breaks, consolidate what actually hurts"**

**Key Learnings from Adversarial Review:**
- Not all duplication is bad duplication
- Semantic intent matters more than syntactic similarity
- Import cycles are a real risk
- Testing and rollback strategies are critical
- Focus on pain points from git history, not code review aesthetics

---

## What We Learned from Git History

Analysis of 6 months of commits to `pkg/vault/` reveals **actual problems**:

```bash
# Real issues that keep coming back:
- Permissions bugs (file/directory ownership/mode)
- Config validation error reporting
- File operation error handling
- Inconsistent logging
```

**Notably ABSENT:**
- No "duplicate code caused this bug" commits
- No "consolidation would have prevented this" issues

**Conclusion:** Structure is less important than operational correctness.

---

## Proven Wins vs Premature Optimization

###  Proven Win: TLS Certificate Generation (COMPLETED)

**Why This Worked:**
- Fixed actual production bug (SANs missing host IP)
- Three implementations drifted and had bugs
- Clear measurable improvement (4096-bit keys, 10-year validity, comprehensive SANs)
- Single source of truth prevents future drift

**Evidence:** User reported SANs issue, we fixed it by consolidating.

### 🔴 Premature Optimization: File I/O Consolidation

**Why This Would Fail:**
- Installation-time `createDirectory` (idempotent, must create) ≠ Runtime `verifyDirectory` (must not create)
- Different semantic intents require different implementations
- Forced consolidation would couple unrelated concerns
- No evidence this causes bugs

**Verdict:** Keep intentional duplication where coupling is worse.

### 🔴 Premature Optimization: Ownership Operations

**Why Three Approaches Exist:**
1. `syscall.Chown` - Bootstrap/low-level (no dependencies)
2. `eos_unix.ChownR` - Runtime operations (with context/logging)
3. TODO placeholders - Acknowledged tech debt

**This is a feature ladder, not confusion.**

**Verdict:** Document the tiers, don't consolidate them.

---

## Easy Wins (Focus Here First)

### Easy Win #1: Vault Configuration Generation 🎯

**Problem:** Two separate config generation systems

**Evidence of Pain:**
```go
// install.go:710-859 (150 lines)
func (vi *VaultInstaller) configure() error {
    // Inline HCL generation with string concatenation
    var storageConfig string
    switch vi.config.StorageBackend {
    case "consul": storageConfig = `storage "consul" { ... }`
    case "raft": storageConfig = fmt.Sprintf(`storage "raft" { ... }`)
    }
    // Mix of templating and sprintf
}

// phase4_config.go:118-171
func WriteVaultHCL(rc *eos_io.RuntimeContext) error {
    params := shared.VaultConfigParams{...}
    hcl, err := shared.RenderVaultConfigRaft(params)
    // Template-based generation
}
```

**Why This Is Confusing:**
- New contributors don't know which to use
- Changes must be made in two places
- Test coverage is split
- Template approach is cleaner but not used in install.go

**Consolidation Plan:**

**Step 1: Create unified config generator**
```go
// pkg/vault/config_generator.go (NEW FILE)

package vault

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// ConfigGenerator generates vault.hcl configuration
type ConfigGenerator struct {
	params ConfigParams
}

// ConfigParams contains all parameters for config generation
type ConfigParams struct {
	// Storage
	StorageBackend string // "raft" or "consul"
	NodeID         string
	DataPath       string
	RetryJoinNodes []shared.RetryJoinNode

	// Network
	APIAddr     string
	ClusterAddr string
	ClusterPort int

	// TLS
	TLSEnabled  bool
	TLSCertPath string
	TLSKeyPath  string

	// UI
	UIEnabled bool

	// Auto-unseal
	AutoUnseal     *AutoUnsealConfig // nil = Shamir seal

	// Logging
	LogLevel string
}

// AutoUnsealConfig contains auto-unseal configuration
type AutoUnsealConfig struct {
	Type string // "awskms", "azurekeyvault", "gcpckms"

	// AWS KMS
	KMSKeyID string
	KMSRegion string

	// Azure Key Vault
	AzureTenantID     string
	AzureClientID     string
	AzureClientSecret string
	AzureVaultName    string
	AzureKeyName      string

	// GCP Cloud KMS
	GCPProject     string
	GCPLocation    string
	GCPKeyRing     string
	GCPCryptoKey   string
	GCPCredentials string
}

// NewConfigGenerator creates a new config generator
func NewConfigGenerator(params ConfigParams) *ConfigGenerator {
	return &ConfigGenerator{params: params}
}

// Generate generates the complete vault.hcl configuration
func (cg *ConfigGenerator) Generate() (string, error) {
	// Use template-based generation (proven to work in phase4_config.go)
	tmpl, err := template.New("vault").Parse(vaultConfigTemplate)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cg.params); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}

	return buf.String(), nil
}

// Validate validates the configuration parameters
func (cg *ConfigGenerator) Validate() error {
	if cg.params.StorageBackend != "raft" && cg.params.StorageBackend != "consul" {
		return fmt.Errorf("unsupported storage backend: %s (supported: raft, consul)", cg.params.StorageBackend)
	}

	if cg.params.StorageBackend == "raft" && cg.params.NodeID == "" {
		return fmt.Errorf("node_id is required for Raft storage")
	}

	if cg.params.TLSEnabled && (cg.params.TLSCertPath == "" || cg.params.TLSKeyPath == "") {
		return fmt.Errorf("tls_cert_path and tls_key_path required when TLS is enabled")
	}

	return nil
}

const vaultConfigTemplate = `# Vault Configuration
# Generated by Eos

ui = {{ .UIEnabled }}

storage "{{ .StorageBackend }}" {
{{- if eq .StorageBackend "raft" }}
  path    = "{{ .DataPath }}/raft"
  node_id = "{{ .NodeID }}"

  {{- if .RetryJoinNodes }}
  retry_join {
    {{- range .RetryJoinNodes }}
    leader_api_addr = "{{ .APIAddr }}"
    {{- end }}
  }
  {{- end }}
{{- else if eq .StorageBackend "consul" }}
  address = "127.0.0.1:8500"
  path    = "vault"
{{- end }}
}

listener "tcp" {
  address     = "0.0.0.0:{{ .ClusterPort }}"
  {{- if .TLSEnabled }}
  tls_cert_file = "{{ .TLSCertPath }}"
  tls_key_file  = "{{ .TLSKeyPath }}"
  {{- else }}
  tls_disable = 1
  {{- end }}
}

{{- if .AutoUnseal }}
seal "{{ .AutoUnseal.Type }}" {
  {{- if eq .AutoUnseal.Type "awskms" }}
  region     = "{{ .AutoUnseal.KMSRegion }}"
  kms_key_id = "{{ .AutoUnseal.KMSKeyID }}"
  {{- else if eq .AutoUnseal.Type "azurekeyvault" }}
  tenant_id     = "{{ .AutoUnseal.AzureTenantID }}"
  client_id     = "{{ .AutoUnseal.AzureClientID }}"
  client_secret = "{{ .AutoUnseal.AzureClientSecret }}"
  vault_name    = "{{ .AutoUnseal.AzureVaultName }}"
  key_name      = "{{ .AutoUnseal.AzureKeyName }}"
  {{- else if eq .AutoUnseal.Type "gcpckms" }}
  project     = "{{ .AutoUnseal.GCPProject }}"
  region      = "{{ .AutoUnseal.GCPLocation }}"
  key_ring    = "{{ .AutoUnseal.GCPKeyRing }}"
  crypto_key  = "{{ .AutoUnseal.GCPCryptoKey }}"
  {{- if .AutoUnseal.GCPCredentials }}
  credentials = "{{ .AutoUnseal.GCPCredentials }}"
  {{- end }}
  {{- end }}
}
{{- end }}

cluster_addr = "{{ .ClusterAddr }}"
api_addr     = "{{ .APIAddr }}"

log_level = "{{ .LogLevel }}"
`
```

**Step 2: Update install.go to use generator**
```go
// In install.go configure() method, replace lines 710-859 with:

func (vi *VaultInstaller) configure() error {
	vi.logger.Info("Configuring Vault")

	// Generate TLS certificates if needed
	if vi.config.TLSEnabled {
		if err := vi.generateTLSCertificate(); err != nil {
			return fmt.Errorf("failed to generate TLS certificate: %w", err)
		}
	}

	// Prepare config parameters
	params := ConfigParams{
		StorageBackend: vi.config.StorageBackend,
		NodeID:         vi.config.NodeID,
		DataPath:       vi.config.DataPath,
		RetryJoinNodes: vi.config.RetryJoinNodes,
		APIAddr:        vi.config.APIAddr,
		ClusterAddr:    vi.config.ClusterAddr,
		ClusterPort:    vi.config.ClusterPort,
		TLSEnabled:     vi.config.TLSEnabled,
		TLSCertPath:    filepath.Join(vi.config.ConfigPath, "tls", "vault.crt"),
		TLSKeyPath:     filepath.Join(vi.config.ConfigPath, "tls", "vault.key"),
		UIEnabled:      vi.config.UIEnabled,
		LogLevel:       vi.config.LogLevel,
	}

	// Add auto-unseal config if enabled
	if vi.config.AutoUnseal {
		params.AutoUnseal = &AutoUnsealConfig{
			Type:              vi.config.AutoUnsealType,
			KMSKeyID:          vi.config.KMSKeyID,
			KMSRegion:         vi.config.KMSRegion,
			// ... other auto-unseal fields
		}
	}

	// Generate configuration
	generator := NewConfigGenerator(params)
	if err := generator.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	configContent, err := generator.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate configuration: %w", err)
	}

	// Write configuration file
	configPath := filepath.Join(vi.config.ConfigPath, "vault.hcl")
	if err := vi.writeFile(configPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write configuration: %w", err)
	}

	vi.logger.Info("Vault configuration written successfully",
		zap.String("path", configPath))

	return nil
}
```

**Step 3: Update phase4_config.go to use generator**
```go
// In phase4_config.go, replace WriteVaultHCL with:

func WriteVaultHCL(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	params := ConfigParams{
		StorageBackend: "raft",
		NodeID:         "node1",
		DataPath:       shared.VaultDataPath,
		ClusterPort:    shared.PortVault,
		APIAddr:        fmt.Sprintf("https://127.0.0.1:%d", shared.PortVault),
		ClusterAddr:    fmt.Sprintf("https://127.0.0.1:%d", shared.PortVault+1),
		TLSEnabled:     true,
		TLSCertPath:    shared.TLSCrt,
		TLSKeyPath:     shared.TLSKey,
		UIEnabled:      true,
		LogLevel:       "info",
	}

	generator := NewConfigGenerator(params)
	if err := generator.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	configContent, err := generator.Generate()
	if err != nil {
		return fmt.Errorf("generate config: %w", err)
	}

	if err := os.WriteFile(shared.VaultConfigPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	log.Info("Vault configuration written", zap.String("path", shared.VaultConfigPath))
	return nil
}
```

**Testing Strategy:**
```go
// config_generator_test.go

func TestConfigGenerator_Raft(t *testing.T) {
	params := ConfigParams{
		StorageBackend: "raft",
		NodeID:         "test-node",
		DataPath:       "/opt/vault/data",
		ClusterPort:    8179,
		// ... other params
	}

	gen := NewConfigGenerator(params)
	config, err := gen.Generate()
	require.NoError(t, err)

	// Verify config contains expected elements
	assert.Contains(t, config, `storage "raft"`)
	assert.Contains(t, config, `node_id = "test-node"`)
	assert.Contains(t, config, `/opt/vault/data/raft`)
}

func TestConfigGenerator_Validation(t *testing.T) {
	tests := []struct {
		name    string
		params  ConfigParams
		wantErr string
	}{
		{
			name: "missing node_id for raft",
			params: ConfigParams{
				StorageBackend: "raft",
				NodeID:         "",
			},
			wantErr: "node_id is required",
		},
		{
			name: "invalid storage backend",
			params: ConfigParams{
				StorageBackend: "file",
			},
			wantErr: "unsupported storage backend",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewConfigGenerator(tt.params)
			err := gen.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
```

**Rollback Plan:**
- Keep old inline generation in install.go commented out for 1 release
- Add feature flag `USE_NEW_CONFIG_GENERATOR` (default: true)
- If issues found, flip flag to false and revert

**Impact:**
- **~200 lines eliminated** from install.go
- **Single source of truth** for config generation
- **Better testability** - config generation isolated
- **Easier to extend** - add new backends by updating template

**Effort:** ~4 hours
- 2 hours: Write config_generator.go
- 1 hour: Update install.go and phase4_config.go
- 1 hour: Write tests

---

### Easy Win #2: Permission Fixing Helper 🎯

**Problem:** Permissions bugs keep recurring in git history

**Evidence from Git:**
```
ddcdf0ef fix: enforce 0600 permissions on vault agent token file
6529c713 fix: ensure parent directory has correct permissions before vault data directory creation
2d5eee0e fix: use context-aware sleep and secure file permissions for secrets
```

**Pattern:** Same permission bugs in different files

**Root Cause:** No standard way to set "vault file permissions"

**Consolidation Plan:**

**Step 1: Create permission helper**
```go
// pkg/vault/permissions.go (NEW FILE)

package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Standard Vault file permissions
const (
	// DirPerms: directories owned by vault:vault
	DirPerms os.FileMode = 0750

	// ConfigPerms: config files readable by vault
	ConfigPerms os.FileMode = 0640

	// SecretPerms: secrets readable only by vault
	SecretPerms os.FileMode = 0600

	// PublicPerms: public files (certs) readable by all
	PublicPerms os.FileMode = 0644
)

// PermissionFixer sets correct permissions for Vault files
type PermissionFixer struct {
	rc    *eos_io.RuntimeContext
	owner string
	group string
}

// NewPermissionFixer creates a new permission fixer
func NewPermissionFixer(rc *eos_io.RuntimeContext) *PermissionFixer {
	return &PermissionFixer{
		rc:    rc,
		owner: "vault",
		group: "vault",
	}
}

// FixDirectory ensures a directory has correct permissions and ownership
// This handles the common pattern: create dir, set perms, set owner
func (pf *PermissionFixer) FixDirectory(path string) error {
	log := otelzap.Ctx(pf.rc.Ctx)

	// Ensure parent directory exists first (fixes recurring bug)
	parentDir := filepath.Dir(path)
	if err := pf.ensureParentExists(parentDir); err != nil {
		return fmt.Errorf("ensure parent directory: %w", err)
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(path, DirPerms); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// Set permissions explicitly (mkdir might not respect umask)
	if err := os.Chmod(path, DirPerms); err != nil {
		return fmt.Errorf("chmod directory: %w", err)
	}

	// Set ownership if running as root
	if os.Geteuid() == 0 {
		if err := pf.setOwnership(path); err != nil {
			return fmt.Errorf("set ownership: %w", err)
		}
	}

	log.Debug("Fixed directory permissions",
		zap.String("path", path),
		zap.String("perms", DirPerms.String()))

	return nil
}

// FixFile ensures a file has correct permissions and ownership
func (pf *PermissionFixer) FixFile(path string, perms os.FileMode) error {
	log := otelzap.Ctx(pf.rc.Ctx)

	// Ensure parent directory exists
	parentDir := filepath.Dir(path)
	if err := pf.FixDirectory(parentDir); err != nil {
		return fmt.Errorf("fix parent directory: %w", err)
	}

	// Set file permissions
	if err := os.Chmod(path, perms); err != nil {
		return fmt.Errorf("chmod file: %w", err)
	}

	// Set ownership if running as root
	if os.Geteuid() == 0 {
		if err := pf.setOwnership(path); err != nil {
			return fmt.Errorf("set ownership: %w", err)
		}
	}

	log.Debug("Fixed file permissions",
		zap.String("path", path),
		zap.String("perms", perms.String()))

	return nil
}

// FixSecretFile sets 0600 permissions on a secret file
// This is the most common operation and the source of bugs
func (pf *PermissionFixer) FixSecretFile(path string) error {
	return pf.FixFile(path, SecretPerms)
}

// FixConfigFile sets 0640 permissions on a config file
func (pf *PermissionFixer) FixConfigFile(path string) error {
	return pf.FixFile(path, ConfigPerms)
}

// FixPublicFile sets 0644 permissions on a public file (like certs)
func (pf *PermissionFixer) FixPublicFile(path string) error {
	return pf.FixFile(path, PublicPerms)
}

// ensureParentExists ensures parent directory exists
// This fixes the recurring bug where we try to create a file in a non-existent parent
func (pf *PermissionFixer) ensureParentExists(parentDir string) error {
	if _, err := os.Stat(parentDir); os.IsNotExist(err) {
		// Parent doesn't exist, create it recursively
		if err := os.MkdirAll(parentDir, DirPerms); err != nil {
			return fmt.Errorf("create parent directory: %w", err)
		}

		// Set ownership on parent
		if os.Geteuid() == 0 {
			if err := pf.setOwnership(parentDir); err != nil {
				return fmt.Errorf("set parent ownership: %w", err)
			}
		}
	}

	return nil
}

// setOwnership sets vault:vault ownership
func (pf *PermissionFixer) setOwnership(path string) error {
	uid, gid, err := eos_unix.LookupUser(pf.rc.Ctx, pf.owner)
	if err != nil {
		return fmt.Errorf("lookup user %s: %w", pf.owner, err)
	}

	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}

	return nil
}
```

**Step 2: Use in agent config (where bugs occurred)**
```go
// In phase13_write_agent_config.go

func WriteVaultAgentConfig(rc *eos_io.RuntimeContext, token string) error {
	log := otelzap.Ctx(rc.Ctx)

	// OLD (bug-prone):
	// tokenFile := filepath.Join(shared.VaultAgentDir, "token")
	// if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil { ... }
	// if err := os.Chown(tokenFile, uid, gid); err != nil { ... }

	// NEW (bug-proof):
	fixer := NewPermissionFixer(rc)

	// Ensure agent directory exists with correct permissions
	if err := fixer.FixDirectory(shared.VaultAgentDir); err != nil {
		return fmt.Errorf("fix agent directory: %w", err)
	}

	// Write token file
	tokenFile := filepath.Join(shared.VaultAgentDir, "token")
	if err := os.WriteFile(tokenFile, []byte(token), SecretPerms); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}

	// Fix permissions and ownership atomically
	if err := fixer.FixSecretFile(tokenFile); err != nil {
		return fmt.Errorf("fix token file permissions: %w", err)
	}

	log.Info("Vault agent token written securely",
		zap.String("path", tokenFile),
		zap.String("perms", "0600"))

	return nil
}
```

**Testing Strategy:**
```go
// permissions_test.go

func TestPermissionFixer_FixDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	testDir := filepath.Join(tmpDir, "vault", "data")

	ctx := context.Background()
	rc := &eos_io.RuntimeContext{Ctx: ctx}
	fixer := NewPermissionFixer(rc)

	// Create directory with fixer
	err := fixer.FixDirectory(testDir)
	require.NoError(t, err)

	// Verify directory exists
	stat, err := os.Stat(testDir)
	require.NoError(t, err)
	assert.True(t, stat.IsDir())

	// Verify permissions (if running as non-root, we can still check)
	assert.Equal(t, DirPerms, stat.Mode().Perm())
}

func TestPermissionFixer_ParentCreation(t *testing.T) {
	// Test the "ensure parent exists" bug fix
	tmpDir := t.TempDir()
	deepPath := filepath.Join(tmpDir, "a", "b", "c", "vault.token")

	ctx := context.Background()
	rc := &eos_io.RuntimeContext{Ctx: ctx}
	fixer := NewPermissionFixer(rc)

	// Write file in non-existent deep path
	err := os.WriteFile(deepPath, []byte("test"), 0600)
	require.Error(t, err) // Should fail without parent

	// Fix permissions (creates parents)
	err = fixer.FixSecretFile(deepPath)
	require.NoError(t, err)

	// Now file should be writable
	err = os.WriteFile(deepPath, []byte("test"), 0600)
	require.NoError(t, err)

	// Verify all parent directories were created
	assert.DirExists(t, filepath.Join(tmpDir, "a"))
	assert.DirExists(t, filepath.Join(tmpDir, "a", "b"))
	assert.DirExists(t, filepath.Join(tmpDir, "a", "b", "c"))
}
```

**Rollback Plan:**
- This is additive, no breaking changes
- Can be adopted gradually file by file
- Old code continues to work

**Impact:**
- **Prevents recurring permission bugs**
- **Single source of truth** for Vault permissions
- **Explicit parent directory handling** (fixes git history bugs)
- **Clear permission semantics** (secret vs config vs public)

**Effort:** ~2 hours
- 1 hour: Write permissions.go
- 30 min: Update phase13 (agent config)
- 30 min: Write tests

---

### Easy Win #3: Config Validation Error Reporting 🎯

**Problem:** Config validation errors are confusing

**Evidence from Git:**
```
9fa8226c fix: improve Vault config validation error reporting
1a9d94ab fix: skip vault config validation if binary not found
```

**Current State:** Validation errors don't say **why** the config is invalid

**Consolidation Plan:**

**Step 1: Add structured validation errors**
```go
// In config_generator.go, enhance Validate() method:

type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
}

func (ve *ValidationError) Error() string {
	return fmt.Sprintf("invalid %s (%v): %s", ve.Field, ve.Value, ve.Message)
}

func (cg *ConfigGenerator) Validate() error {
	var errs []error

	// Storage backend validation
	if cg.params.StorageBackend != "raft" && cg.params.StorageBackend != "consul" {
		errs = append(errs, &ValidationError{
			Field:   "storage_backend",
			Value:   cg.params.StorageBackend,
			Message: "must be 'raft' or 'consul'",
		})
	}

	// Raft-specific validation
	if cg.params.StorageBackend == "raft" {
		if cg.params.NodeID == "" {
			errs = append(errs, &ValidationError{
				Field:   "node_id",
				Value:   "",
				Message: "required when using Raft storage",
			})
		}
	}

	// TLS validation
	if cg.params.TLSEnabled {
		if cg.params.TLSCertPath == "" {
			errs = append(errs, &ValidationError{
				Field:   "tls_cert_path",
				Value:   "",
				Message: "required when TLS is enabled",
			})
		}
		if cg.params.TLSKeyPath == "" {
			errs = append(errs, &ValidationError{
				Field:   "tls_key_path",
				Value:   "",
				Message: "required when TLS is enabled",
			})
		}

		// Check if cert files exist
		if _, err := os.Stat(cg.params.TLSCertPath); os.IsNotExist(err) {
			errs = append(errs, &ValidationError{
				Field:   "tls_cert_path",
				Value:   cg.params.TLSCertPath,
				Message: "certificate file does not exist",
			})
		}
		if _, err := os.Stat(cg.params.TLSKeyPath); os.IsNotExist(err) {
			errs = append(errs, &ValidationError{
				Field:   "tls_key_path",
				Value:   cg.params.TLSKeyPath,
				Message: "key file does not exist",
			})
		}
	}

	if len(errs) > 0 {
		return &MultiValidationError{Errors: errs}
	}

	return nil
}

type MultiValidationError struct {
	Errors []error
}

func (mve *MultiValidationError) Error() string {
	var msgs []string
	for _, err := range mve.Errors {
		msgs = append(msgs, err.Error())
	}
	return fmt.Sprintf("validation failed:\n  - %s", strings.Join(msgs, "\n  - "))
}
```

**Impact:**
- **Clear error messages** instead of generic "invalid config"
- **Actionable feedback** - tells you exactly what to fix
- **Multiple errors at once** - see all problems, not just first one

**Effort:** ~1 hour (enhance existing Validate() method)

---

## Not Doing (Intentional Duplication)

### ❌ File I/O Consolidation

**Why Not:**
- Installation-time operations have different semantics than runtime operations
- `createDirectory` (must create) ≠ `verifyDirectory` (must not create)
- Consolidation would couple unrelated concerns
- No evidence in git history this causes bugs

**Verdict:** Keep as-is, document intent.

### ❌ Ownership Operations Consolidation

**Why Not:**
- Three tiers serve different purposes:
  1. Bootstrap (syscall.Chown - no deps)
  2. Runtime (eos_unix - with context)
  3. Tech debt (TODOs - migrate to tier 2)
- This is a feature ladder, not duplication
- Forced consolidation would break bootstrap sequence

**Verdict:** Document tiers, don't consolidate.

### ❌ Network Operations Consolidation

**Why Not:**
- Different retry strategies for different scenarios
- Need context cancellation (original proposal missing this)
- Composability > monolithic abstraction
- No evidence of bugs from current approach

**Verdict:** Keep flexible primitives, don't create rigid abstraction.

### ❌ Command Execution Enforcement

**Why Not:**
- CommandRunner exists but isn't used everywhere
- Need to understand WHY before enforcing
- Linting rules without investigation is cargo culting

**Verdict:** Investigate first, then decide.

---

## Testing Strategy

### For Each Easy Win:

1. **Write tests FIRST**
   - Test consolidated code before migration
   - Ensure new code works in isolation

2. **Migration Pattern:**
   - Update one call site at a time
   - Keep old code working during transition
   - Run full test suite after each change

3. **Integration Tests:**
   - Keep existing integration tests running
   - They validate behavior hasn't changed

4. **Feature Flags:**
   - Use flags for gradual rollout
   - Easy to revert if issues found

### Testing Pyramid:

```
         /\
        /  \       Integration tests (few)
       /____\      - Full vault installation
      /      \     - End-to-end workflows
     /  Unit  \    Unit tests (many)
    /__________\   - Config generation
                   - Permission fixing
                   - Validation
```

---

## Rollback Strategy

### For Config Generator:

**Week 1:** Add new code, keep old code
```go
if os.Getenv("USE_NEW_CONFIG_GENERATOR") == "true" {
    // Use ConfigGenerator
} else {
    // Use old inline generation
}
```

**Week 2:** Default to new, old code available
```go
if os.Getenv("USE_OLD_CONFIG_GENERATOR") != "true" {
    // Use ConfigGenerator (default)
} else {
    // Use old inline generation
}
```

**Week 3:** Remove old code if no issues

### For Permission Fixer:

**This is additive - no rollback needed**
- Old code continues to work
- New code is opt-in
- Can adopt gradually

---

## Import Cycle Analysis

### Proposed New Files:

1. `config_generator.go` - imports: `text/template`, `pkg/shared`
2. `permissions.go` - imports: `pkg/eos_io`, `pkg/eos_unix`

### Dependency Graph:

```
config_generator.go
  └─> pkg/shared (✓ no cycle)

permissions.go
  └─> pkg/eos_io (✓ no cycle)
  └─> pkg/eos_unix (✓ no cycle)

install.go
  └─> config_generator.go (✓ no cycle)
  └─> permissions.go (✓ no cycle)
```

**Analysis:** No import cycles will be created.

---

## Success Metrics

### Easy Win #1: Config Generator

**Before:**
- 2 separate config generation systems
- 150 lines of inline string concatenation in install.go
- Config changes require updates in 2 places
- Hard to test config generation

**After:**
- 1 unified config generator
- ~150 lines eliminated from install.go
- Single source of truth
- Testable in isolation
- Easier to add new storage backends

### Easy Win #2: Permission Fixer

**Before:**
- Permission bugs recur in git history
- No standard way to set vault permissions
- Parent directory bugs
- Inconsistent ownership handling

**After:**
- Standard permission constants
- Atomic permission + ownership setting
- Parent directory handling built-in
- Clear permission semantics (secret/config/public)

### Easy Win #3: Config Validation

**Before:**
- Generic "invalid config" errors
- Hard to debug what's wrong
- Only see first error

**After:**
- Specific field-level errors
- Actionable messages
- See all validation errors at once

---

## Timeline

### Week 1: Config Generator (Easy Win #1)
- **Monday**: Write config_generator.go + tests
- **Tuesday**: Update install.go to use generator
- **Wednesday**: Update phase4_config.go to use generator
- **Thursday**: Integration testing
- **Friday**: Deploy with feature flag

### Week 2: Permission Fixer (Easy Win #2)
- **Monday**: Write permissions.go + tests
- **Tuesday**: Update phase13 (agent config)
- **Wednesday**: Find other permission bugs in codebase
- **Thursday**: Update those files
- **Friday**: Integration testing

### Week 3: Config Validation (Easy Win #3)
- **Monday**: Enhance Validate() with structured errors
- **Tuesday**: Update all validation call sites
- **Wednesday**: Write tests
- **Thursday**: Integration testing
- **Friday**: Documentation

### Week 4: Polish & Review
- Remove feature flags if no issues
- Update PATTERNS.md with new patterns
- Code review and feedback
- Document lessons learned

---

## Next Steps

1.  Review and approve this revised plan
2.  Create feature branch: `refactor/vault-easy-wins`
3.  Week 1: Config Generator
4.  Week 2: Permission Fixer
5.  Week 3: Config Validation
6.  Week 4: Polish

---

## Lessons from Adversarial Review

### What We Learned:

1. **Not all duplication is bad** - Semantic intent matters
2. **Import cycles are real** - Design package structure first
3. **Testing strategy is critical** - Write tests before migrating
4. **Rollback plans are essential** - Use feature flags
5. **Focus on pain points** - Git history reveals real problems
6. **Premature abstraction hurts** - Only abstract when you feel the pain

### What We Avoided:

1. ❌ Consolidating file I/O (different semantic intents)
2. ❌ Consolidating ownership (three tiers serve different purposes)
3. ❌ Rigid network abstractions (need composability)
4. ❌ Enforcing CommandRunner without investigation
5. ❌ Creating packages without dependency analysis

### New Philosophy:

~~"Consolidate all duplication"~~
 **"Fix what breaks, consolidate what hurts, document intentional duplication"**

---

*This consolidation follows the principle: "Fix real problems with measured solutions."*
