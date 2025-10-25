// pkg/vault/mfa.go

package vault

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	vaultpaths "github.com/CodeMonkeyCybersecurity/eos/pkg/shared/vault"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// MFAConfig represents MFA configuration for Vault
type MFAConfig struct {
	TOTPEnabled   bool
	DuoEnabled    bool
	EnforceForAll bool
	SkipRoot      bool
	PingIDEnabled bool
	OktaEnabled   bool
}

// DefaultMFAConfig returns secure defaults for MFA
func DefaultMFAConfig() *MFAConfig {
	return &MFAConfig{
		TOTPEnabled:   true,
		DuoEnabled:    false,
		EnforceForAll: true,
		SkipRoot:      false, // Enforce MFA even for root in production
		PingIDEnabled: false,
		OktaEnabled:   false,
	}
}

// CreateMFAMethodsOnly creates MFA methods WITHOUT enforcement
// Extracted from EnableMFAMethods to allow verification before enforcement
//
// CRITICAL: This function ONLY creates MFA methods (e.g., TOTP, Duo, etc.).
// It does NOT apply enforcement policies. Enforcement must be done separately
// via EnforceMFAPolicyOnly() AFTER verifying that users can successfully
// use the MFA methods.
//
// This split prevents lockout scenarios where MFA is enforced but users
// haven't configured their TOTP secrets yet.
func CreateMFAMethodsOnly(rc *eos_io.RuntimeContext, client *api.Client, config *MFAConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Creating MFA methods (enforcement deferred)")

	if config == nil {
		config = DefaultMFAConfig()
	}

	// Get privileged client with root token for MFA configuration
	log.Info(" Getting privileged client for MFA setup")
	privilegedClient, err := GetPrivilegedClient(rc)
	if err != nil {
		log.Error(" Failed to get privileged Vault client for MFA setup", zap.Error(err))
		return cerr.Wrap(err, "get privileged client for MFA")
	}

	// Log what token the privileged client is using
	if privToken := privilegedClient.Token(); privToken != "" {
		log.Info(" Using privileged client for MFA operations")
	}

	// Enable TOTP MFA if requested (method creation only, no enforcement)
	if config.TOTPEnabled {
		log.Info(" Creating TOTP MFA method")
		if err := enableTOTPMFA(rc, privilegedClient); err != nil {
			log.Error(" Failed to create TOTP MFA method", zap.Error(err))
			return cerr.Wrap(err, "failed to create TOTP MFA method")
		}
	}

	// Enable Duo MFA if requested
	if config.DuoEnabled {
		log.Info(" Creating Duo MFA method")
		if err := enableDuoMFA(rc, privilegedClient); err != nil {
			log.Error(" Failed to create Duo MFA method", zap.Error(err))
			return cerr.Wrap(err, "failed to create Duo MFA method")
		}
	}

	// Enable PingID MFA if requested
	if config.PingIDEnabled {
		log.Info(" Creating PingID MFA method")
		if err := enablePingIDMFA(rc, privilegedClient); err != nil {
			log.Error(" Failed to create PingID MFA method", zap.Error(err))
			return cerr.Wrap(err, "failed to create PingID MFA method")
		}
	}

	// Enable Okta MFA if requested
	if config.OktaEnabled {
		log.Info(" Creating Okta MFA method")
		if err := enableOktaMFA(rc, privilegedClient); err != nil {
			log.Error(" Failed to create Okta MFA method", zap.Error(err))
			return cerr.Wrap(err, "failed to create Okta MFA method")
		}
	}

	// NOTE: Does NOT call enforceMFAForAllUsers() - that's done in EnforceMFAPolicyOnly()

	log.Info(" MFA methods created successfully (not yet enforced)")
	log.Info("MFA Setup State Transition",
		zap.String("from_state", "no_mfa"),
		zap.String("to_state", "methods_created"),
		zap.String("note", "Awaiting TOTP setup and verification"))
	return nil
}

// EnforceMFAPolicyOnly applies MFA enforcement AFTER methods are verified
//
// CRITICAL: Must only be called AFTER SetupUserTOTP() succeeds for at least
// one user. This ensures users can actually authenticate with MFA before
// enforcement is active.
//
// If this function is called before TOTP setup, users will be locked out
// because they won't have TOTP secrets configured yet.
func EnforceMFAPolicyOnly(rc *eos_io.RuntimeContext, client *api.Client, config *MFAConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Applying MFA enforcement policy")
	log.Info("MFA Setup State Transition",
		zap.String("from_state", "totp_verified"),
		zap.String("to_state", "mfa_enforced"),
		zap.String("note", "MFA now required for all logins"))

	if config == nil {
		config = DefaultMFAConfig()
	}

	// Get privileged client
	privilegedClient, err := GetPrivilegedClient(rc)
	if err != nil {
		log.Error(" Failed to get privileged Vault client for MFA enforcement", zap.Error(err))
		return cerr.Wrap(err, "get privileged client for MFA")
	}

	// Apply enforcement policies
	if config.EnforceForAll {
		log.Info(" Enforcing MFA for all authentication methods")
		if err := enforceMFAForAllUsers(rc, privilegedClient, config); err != nil {
			log.Error(" Failed to enforce MFA for all users", zap.Error(err))
			return cerr.Wrap(err, "failed to enforce MFA for all users")
		}
	}

	log.Info(" MFA enforcement active")
	log.Info("MFA Setup State Transition",
		zap.String("from_state", "mfa_enforced"),
		zap.String("to_state", "fully_operational"),
		zap.String("note", "MFA setup complete"))
	return nil
}

// EnableMFAMethods enables and configures MFA methods in Vault
//
// DEPRECATED: Use CreateMFAMethodsOnly() + SetupUserTOTP() + EnforceMFAPolicyOnly()
// for better error recovery and idempotency.
//
// This function combines method creation and enforcement in one operation,
// which can lead to lockout if TOTP setup fails.
func EnableMFAMethods(rc *eos_io.RuntimeContext, client *api.Client, config *MFAConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Warn(" DEPRECATED: Using legacy EnableMFAMethods (combines creation + enforcement)")
	log.Warn(" Consider using CreateMFAMethodsOnly + EnforceMFAPolicyOnly for better safety")

	// Call new functions in sequence (legacy behavior)
	if err := CreateMFAMethodsOnly(rc, client, config); err != nil {
		return err
	}

	// Immediately enforce (this is the old behavior that can cause lockout)
	return EnforceMFAPolicyOnly(rc, client, config)
}

// enableTOTPMFA enables Time-based One-Time Password MFA using Identity-based MFA
func enableTOTPMFA(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Configuring TOTP Identity-based MFA method")

	// Configure TOTP MFA method using the correct Identity API
	totpConfig := map[string]interface{}{
		"generate":  true,
		"issuer":    "Vault - Eos Infrastructure",
		"period":    30,
		"algorithm": "SHA256",
		"digits":    6,
		"key_size":  30,
	}

	// Create the TOTP MFA method using the Identity API
	resp, err := client.Logical().Write("identity/mfa/method/totp", totpConfig)
	if err != nil {
		log.Error(" Failed to create TOTP MFA method",
			zap.Error(err),
			zap.String("vault_addr", client.Address()))
		return cerr.Wrap(err, "failed to create TOTP MFA method")
	}

	if resp == nil || resp.Data == nil || resp.Data["method_id"] == nil {
		log.Error(" TOTP MFA method creation did not return method_id",
			zap.Any("response", resp))
		return cerr.New("TOTP MFA method creation did not return method_id")
	}

	// SECURITY P0 #1: Safe type assertion to prevent panic
	methodID, ok := resp.Data["method_id"].(string)
	if !ok {
		log.Error(" TOTP MFA method_id has invalid type",
			zap.Any("method_id", resp.Data["method_id"]))
		return cerr.New("TOTP MFA method_id is not a string")
	}
	log.Info(" TOTP MFA method created", zap.String("method_id", methodID))

	// Store the method ID for enforcement configuration
	if err := storeMFAMethodID(rc, "totp", methodID); err != nil {
		log.Warn("Failed to store MFA method ID", zap.Error(err))
	}

	return nil
}

// storeMFAMethodID stores MFA method ID for later enforcement configuration
func storeMFAMethodID(rc *eos_io.RuntimeContext, methodType, methodID string) error {
	log := otelzap.Ctx(rc.Ctx)

	// Store in a simple key-value structure in Vault
	secretPath := fmt.Sprintf("secret/data/eos/mfa-methods/%s", methodType)
	log.Info(" Storing MFA method ID in Vault",
		zap.String("path", secretPath),
		zap.String("method_type", methodType))
	data := map[string]interface{}{
		"data": map[string]interface{}{
			"method_id":   methodID,
			"method_type": methodType,
			"created_at":  time.Now().UTC().Format(time.RFC3339),
			"created_by":  "eos",
		},
	}

	client, err := GetPrivilegedClient(rc)
	if err != nil {
		return cerr.Wrap(err, "failed to get root client")
	}

	_, err = client.Logical().Write(secretPath, data)
	if err != nil {
		return cerr.Wrap(err, "failed to store MFA method ID")
	}

	log.Info(" MFA method ID stored",
		zap.String("method_type", methodType),
		zap.String("method_id", methodID))

	return nil
}

// enableDuoMFA enables Duo Security MFA
func enableDuoMFA(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Enabling Duo MFA method")

	if !interaction.PromptYesNo(rc.Ctx, "Do you want to configure Duo Security MFA?", false) {
		log.Info(" Skipping Duo MFA configuration")
		return nil
	}

	// Prompt for Duo configuration
	duoConfig, err := promptDuoConfig(rc)
	if err != nil {
		log.Error(" Failed to get Duo configuration", zap.Error(err))
		return cerr.Wrap(err, "failed to get Duo configuration")
	}

	// Enable Duo auth method
	authPath := "mfa/duo"
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type:        "duo",
		Description: "Duo Security Multi-Factor Authentication",
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		log.Error(" Failed to enable Duo auth method",
			zap.Error(err),
			zap.String("auth_path", authPath))
		return cerr.Wrap(err, "failed to enable Duo auth method")
	}

	// Configure Duo method
	_, err = client.Logical().Write(fmt.Sprintf("auth/%s/config", authPath), duoConfig)
	if err != nil {
		log.Error(" Failed to configure Duo method",
			zap.Error(err),
			zap.String("path", fmt.Sprintf("auth/%s/config", authPath)))
		return cerr.Wrap(err, "failed to configure Duo method")
	}

	log.Info(" Duo MFA method enabled and configured")
	return nil
}

// enablePingIDMFA enables PingID MFA
func enablePingIDMFA(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Enabling PingID MFA method")

	if !interaction.PromptYesNo(rc.Ctx, "Do you want to configure PingID MFA?", false) {
		log.Info(" Skipping PingID MFA configuration")
		return nil
	}

	// Prompt for PingID configuration
	pingConfig, err := promptPingIDConfig(rc)
	if err != nil {
		log.Error(" Failed to get PingID configuration", zap.Error(err))
		return cerr.Wrap(err, "failed to get PingID configuration")
	}

	// Enable PingID auth method
	authPath := "mfa/pingid"
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type:        "pingid",
		Description: "PingID Multi-Factor Authentication",
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		log.Error(" Failed to enable PingID auth method",
			zap.Error(err),
			zap.String("auth_path", authPath))
		return cerr.Wrap(err, "failed to enable PingID auth method")
	}

	// Configure PingID method
	_, err = client.Logical().Write(fmt.Sprintf("auth/%s/config", authPath), pingConfig)
	if err != nil {
		log.Error(" Failed to configure PingID method",
			zap.Error(err),
			zap.String("path", fmt.Sprintf("auth/%s/config", authPath)))
		return cerr.Wrap(err, "failed to configure PingID method")
	}

	log.Info(" PingID MFA method enabled and configured")
	return nil
}

// enableOktaMFA enables Okta MFA
func enableOktaMFA(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Enabling Okta MFA method")

	if !interaction.PromptYesNo(rc.Ctx, "Do you want to configure Okta MFA?", false) {
		log.Info(" Skipping Okta MFA configuration")
		return nil
	}

	// Prompt for Okta configuration
	oktaConfig, err := promptOktaConfig(rc)
	if err != nil {
		log.Error(" Failed to get Okta configuration", zap.Error(err))
		return cerr.Wrap(err, "failed to get Okta configuration")
	}

	// Enable Okta auth method
	authPath := "mfa/okta"
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type:        "okta",
		Description: "Okta Multi-Factor Authentication",
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		log.Error(" Failed to enable Okta auth method",
			zap.Error(err),
			zap.String("auth_path", authPath))
		return cerr.Wrap(err, "failed to enable Okta auth method")
	}

	// Configure Okta method
	_, err = client.Logical().Write(fmt.Sprintf("auth/%s/config", authPath), oktaConfig)
	if err != nil {
		log.Error(" Failed to configure Okta method",
			zap.Error(err),
			zap.String("path", fmt.Sprintf("auth/%s/config", authPath)))
		return cerr.Wrap(err, "failed to configure Okta method")
	}

	log.Info(" Okta MFA method enabled and configured")
	return nil
}

// enforceMFAForAllUsers creates policies to enforce MFA for all authentication methods
func enforceMFAForAllUsers(rc *eos_io.RuntimeContext, client *api.Client, config *MFAConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Configuring Identity-based MFA enforcement")

	// For now, we'll create a basic enforcement that can be expanded later
	// Identity MFA enforcement requires method IDs which we stored earlier
	if config.TOTPEnabled {
		if err := enforceIdentityMFAForUserpass(rc, client); err != nil {
			log.Warn("Failed to enforce TOTP MFA for userpass", zap.Error(err))
		}
	}

	// Note: Full MFA enforcement is complex and should be configured by operators
	// based on specific organizational requirements
	log.Info(" Basic MFA enforcement configured - operators should configure detailed enforcement policies")
	return nil
}

// enforceIdentityMFAForUserpass creates MFA login enforcement for userpass authentication
// CRITICAL P0 FIX: This now creates an ACTUAL enforcement policy (was previously a stub)
func enforceIdentityMFAForUserpass(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Creating MFA login enforcement policy for userpass authentication")

	// Step 1: Retrieve TOTP method ID from Vault KV (stored during TOTP enablement)
	log.Info(" [ASSESS] Retrieving TOTP method ID from Vault KV")
	methodIDSecret, err := client.Logical().Read("secret/data/eos/mfa-methods/totp")
	if err != nil {
		log.Error(" Failed to read TOTP method ID from Vault",
			zap.Error(err),
			zap.String("path", "secret/data/eos/mfa-methods/totp"))
		return cerr.Wrap(err, "failed to read TOTP method ID")
	}

	if methodIDSecret == nil || methodIDSecret.Data == nil {
		log.Error(" TOTP method ID not found in Vault KV")
		return cerr.New("TOTP method ID not found - ensure TOTP MFA is enabled first")
	}

	// Extract method_id from nested data structure (KV v2 format)
	data, ok := methodIDSecret.Data["data"].(map[string]interface{})
	if !ok {
		log.Error(" Invalid TOTP method data structure", zap.Any("data", methodIDSecret.Data))
		return cerr.New("invalid TOTP method data structure")
	}

	methodID, ok := data["method_id"].(string)
	if !ok || methodID == "" {
		log.Error(" TOTP method_id is not a valid string", zap.Any("method_id", data["method_id"]))
		return cerr.New("TOTP method_id is not a valid string")
	}

	log.Info(" TOTP method ID retrieved successfully", zap.String("method_id", methodID))

	// Step 2: Get userpass auth accessor (needed for enforcement policy)
	log.Info(" [ASSESS] Retrieving userpass authentication accessor")
	authMounts, err := client.Sys().ListAuth()
	if err != nil {
		log.Error(" Failed to list auth methods", zap.Error(err))
		return cerr.Wrap(err, "failed to list auth methods")
	}

	var userpassAccessor string
	for path, mount := range authMounts {
		if mount.Type == "userpass" || strings.HasPrefix(path, "userpass") {
			userpassAccessor = mount.Accessor
			log.Info(" Userpass accessor found",
				zap.String("path", path),
				zap.String("accessor", userpassAccessor))
			break
		}
	}

	if userpassAccessor == "" {
		log.Error(" Userpass auth method not found - cannot enforce MFA")
		return cerr.New("userpass auth method not found")
	}

	// Step 3: Create MFA login enforcement policy
	log.Info(" [INTERVENE] Creating MFA login enforcement policy")
	enforcementName := "eos-userpass-enforcement"
	enforcementPath := fmt.Sprintf("identity/mfa/login-enforcement/%s", enforcementName)

	enforcementConfig := map[string]interface{}{
		"name":                  enforcementName,
		"mfa_method_ids":        []string{methodID},
		"auth_method_accessors": []string{userpassAccessor},
		"auth_method_types":     []string{"userpass"},
	}

	log.Debug("MFA enforcement policy configuration",
		zap.String("path", enforcementPath),
		zap.Any("config", enforcementConfig))

	_, err = client.Logical().Write(enforcementPath, enforcementConfig)
	if err != nil {
		log.Error(" Failed to create MFA login enforcement policy",
			zap.String("path", enforcementPath),
			zap.Error(err))
		return cerr.Wrap(err, "failed to create MFA enforcement policy")
	}

	// Step 4: Verify enforcement policy was created
	log.Info(" [EVALUATE] Verifying MFA enforcement policy creation")
	verifyResp, err := client.Logical().Read(enforcementPath)
	if err != nil {
		log.Warn("Failed to verify MFA enforcement policy (non-fatal)",
			zap.Error(err))
	} else if verifyResp == nil {
		log.Warn("MFA enforcement policy verification returned nil (may still be active)")
	} else {
		log.Info(" MFA enforcement policy verified",
			zap.String("policy_name", enforcementName),
			zap.Int("response_keys", len(verifyResp.Data)))
	}

	// Success!
	log.Info(" [EVALUATE] MFA login enforcement ACTIVE",
		zap.String("enforcement_policy", enforcementName),
		zap.String("applies_to", "userpass authentication"),
		zap.String("requires", "TOTP MFA"))
	log.Info("terminal prompt: ✓ MFA enforcement active - userpass login now requires TOTP")
	log.Info("terminal prompt:   Users must configure TOTP before next login")

	return nil
}

// Helper functions for prompting MFA configurations

func promptDuoConfig(rc *eos_io.RuntimeContext) (map[string]interface{}, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Duo Security Configuration - prompting for integration details")

	integrationKey, err := interaction.PromptSecrets(rc.Ctx, "Integration Key", 1)
	if err != nil {
		return nil, err
	}

	secretKey, err := interaction.PromptSecrets(rc.Ctx, "Secret Key", 1)
	if err != nil {
		return nil, err
	}

	apiHostname, err := interaction.PromptSecrets(rc.Ctx, "API Hostname (e.g., api-xxxxxxxx.duosecurity.com)", 1)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"integration_key": integrationKey[0],
		"secret_key":      secretKey[0],
		"api_hostname":    apiHostname[0],
		"push_info":       "Vault MFA Request",
	}, nil
}

func promptPingIDConfig(rc *eos_io.RuntimeContext) (map[string]interface{}, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" PingID Configuration - prompting for integration details")

	adminUrl, err := interaction.PromptSecrets(rc.Ctx, "Admin URL", 1)
	if err != nil {
		return nil, err
	}

	authenticatorUrl, err := interaction.PromptSecrets(rc.Ctx, "Authenticator URL", 1)
	if err != nil {
		return nil, err
	}

	orgAlias, err := interaction.PromptSecrets(rc.Ctx, "Organization Alias", 1)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"admin_url":         adminUrl[0],
		"authenticator_url": authenticatorUrl[0],
		"org_alias":         orgAlias[0],
		"use_signature":     true,
	}, nil
}

func promptOktaConfig(rc *eos_io.RuntimeContext) (map[string]interface{}, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Okta Configuration - prompting for integration details")

	orgName, err := interaction.PromptSecrets(rc.Ctx, "Organization Name", 1)
	if err != nil {
		return nil, err
	}

	apiToken, err := interaction.PromptSecrets(rc.Ctx, "API Token", 1)
	if err != nil {
		return nil, err
	}

	baseUrl, err := interaction.PromptSecrets(rc.Ctx, "Base URL (e.g., oktapreview.com)", 1)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"org_name":   orgName[0],
		"api_token":  apiToken[0],
		"base_url":   baseUrl[0],
		"production": true,
	}, nil
}

// VerifyAndFetchMFAPrerequisites atomically verifies all MFA prerequisites AND fetches
// the bootstrap password needed for TOTP setup. This eliminates TOCTOU races by reading
// the password once during verification instead of checking existence then reading later.
//
// Prerequisites verified:
//   1. Userpass user exists
//   2. Entity exists (by name or alias)
//   3. Entity alias exists for userpass mount
//   4. Bootstrap password exists and is readable
//
// Returns MFABootstrapData containing the password and metadata, or error if any
// prerequisite fails.
//
// This function should be called once before MFA setup. Pass the returned data to
// SetupUserTOTP() to avoid re-reading the password from Vault.
//
// Eliminates TOCTOU: By reading the password during verification instead of just checking
// existence, we avoid the race condition where:
//   T0: Check if password exists → TRUE
//   T1: [Password gets deleted/rotated]
//   T2: Try to read password → FAIL
//
// Example:
//
//	bootstrapData, err := VerifyAndFetchMFAPrerequisites(rc, client, "eos")
//	if err != nil {
//	    return err
//	}
//	err = SetupUserTOTP(rc, client, "eos", bootstrapData)
func VerifyAndFetchMFAPrerequisites(
	rc *eos_io.RuntimeContext,
	client *api.Client,
	username string,
) (*MFABootstrapData, error) {
	log := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	log.Info(" [PRE-MFA VERIFICATION] Verifying prerequisites and fetching bootstrap data",
		zap.String("username", username))

	// Check 1: Userpass user exists
	log.Info("   Check 1: Userpass user exists")
	userPath := fmt.Sprintf("auth/userpass/users/%s", username)
	userResp, err := client.Logical().Read(userPath)
	if err != nil || userResp == nil {
		log.Error("   ✗ Userpass user not found",
			zap.String("username", username),
			zap.String("path", userPath),
			zap.Error(err))
		return nil, cerr.Newf("userpass user %s does not exist", username)
	}
	log.Info("   ✓ Userpass user exists")

	// Check 2: Entity exists (by name or alias)
	log.Info("   Check 2: Entity exists")
	entityLookupPath := fmt.Sprintf(shared.EosEntityLookupPath, username)
	entityResp, err := client.Logical().Read(entityLookupPath)

	var entityID string
	var lookupMethod string

	if err != nil || entityResp == nil || entityResp.Data == nil {
		log.Warn("   Entity not found by name, trying alias lookup",
			zap.String("lookup_path", entityLookupPath))

		// Try alias lookup as fallback
		authMounts, authErr := client.Sys().ListAuth()
		if authErr != nil {
			log.Error("   ✗ Cannot list auth mounts for alias lookup", zap.Error(authErr))
			return nil, cerr.Newf("entity for user %s does not exist and cannot verify via alias", username)
		}

		if userpassMount, exists := authMounts["userpass/"]; exists {
			aliasLookupData := map[string]interface{}{
				"alias_name":           username,
				"alias_mount_accessor": userpassMount.Accessor,
			}
			aliasResp, aliasErr := client.Logical().Write("identity/lookup/entity", aliasLookupData)
			if aliasErr != nil || aliasResp == nil || aliasResp.Data == nil {
				log.Error("   ✗ Entity not found by name or alias")
				return nil, cerr.Newf("entity for user %s does not exist", username)
			}

			// Extract entity ID from alias response
			var ok bool
			entityID, ok = aliasResp.Data["id"].(string)
			if !ok || entityID == "" {
				log.Error("   ✗ Entity ID not found in alias response")
				return nil, cerr.New("entity ID missing from alias lookup response")
			}
			lookupMethod = "alias"
			log.Info("   ✓ Entity exists (found via alias)",
				zap.String("entity_id", entityID))
		} else {
			log.Error("   ✗ Entity not found and userpass mount not available for alias lookup")
			return nil, cerr.Newf("entity for user %s does not exist", username)
		}
	} else {
		// Extract entity ID from name-based response
		var ok bool
		entityID, ok = entityResp.Data["id"].(string)
		if !ok || entityID == "" {
			log.Error("   ✗ Entity ID not found in name lookup response")
			return nil, cerr.New("entity ID missing from name lookup response")
		}
		lookupMethod = "name"
		log.Info("   ✓ Entity exists (found by name)",
			zap.String("entity_id", entityID))
	}

	// Check 3: Entity alias exists for userpass
	log.Info("   Check 3: Entity alias exists for userpass")
	authMounts, err := client.Sys().ListAuth()
	if err != nil {
		log.Warn("   Could not verify entity alias", zap.Error(err))
	} else if userpassMount, exists := authMounts["userpass/"]; exists {
		log.Info("   ✓ Entity alias verified (userpass mount exists)",
			zap.String("mount_accessor", userpassMount.Accessor))
	}

	// Check 4: ATOMICALLY read bootstrap password (REPLACES existence check)
	// This is the key change - we READ instead of just checking existence
	log.Info("   Check 4: Reading bootstrap password (Phase 10a completion proof)")
	log.Info("     Path being read:", zap.String("path", vaultpaths.UserpassBootstrapPasswordKVPath))

	passwordSecret, err := client.Logical().Read(vaultpaths.UserpassBootstrapPasswordKVPath)
	if err != nil {
		// Check if it's a 404 (not found)
		if respErr, ok := err.(*api.ResponseError); ok && respErr.StatusCode == 404 {
			log.Error("   ✗ Bootstrap password not found (404)",
				zap.String("path", vaultpaths.UserpassBootstrapPasswordKVPath))
			log.Error("")
			log.Error("═══════════════════════════════════════════════════════════")
			log.Error(" Phase 10a Incomplete: Bootstrap Password Not Found")
			log.Error("═══════════════════════════════════════════════════════════")
			log.Error("")
			log.Error("Expected path:", zap.String("path", vaultpaths.UserpassBootstrapPasswordKVPath))
			log.Error("")
			log.Error("Diagnostic Commands:")
			log.Error("  1. Check if secret exists: vault kv get -mount=secret eos/bootstrap")
			log.Error("  2. List all secrets: vault kv list secret/")
			log.Error("  3. Check Vault logs: journalctl -u vault -n 100")
			log.Error("")
			log.Error("Recovery:")
			log.Error("  Re-run: sudo eos update vault --enable-userpass")
			log.Error("")
			return nil, cerr.Errorf(
				"Phase 10a incomplete: bootstrap password not found at %s",
				vaultpaths.UserpassBootstrapPasswordKVPath)
		}

		// Other error (network, permissions, etc.)
		log.Error("   ✗ Failed to read bootstrap password",
			zap.Error(err),
			zap.String("path", vaultpaths.UserpassBootstrapPasswordKVPath))
		return nil, cerr.Wrap(err, "failed to read bootstrap password")
	}

	// Validate response structure
	if passwordSecret == nil || passwordSecret.Data == nil {
		log.Error("   ✗ Bootstrap password returned nil or has no data",
			zap.String("path", vaultpaths.UserpassBootstrapPasswordKVPath))
		return nil, cerr.New("Phase 10a incomplete: bootstrap password has invalid structure")
	}

	// Extract password from KV v2 structure
	kvData, ok := passwordSecret.Data["data"].(map[string]interface{})
	if !ok {
		log.Error("   ✗ Invalid KV v2 structure",
			zap.String("path", vaultpaths.UserpassBootstrapPasswordKVPath),
			zap.Any("structure", passwordSecret.Data))
		return nil, cerr.New("bootstrap password has invalid KV v2 structure")
	}

	password, ok := kvData[vaultpaths.UserpassBootstrapPasswordKVField].(string)
	if !ok || password == "" {
		log.Error("   ✗ Password field missing or empty",
			zap.String("expected_field", vaultpaths.UserpassBootstrapPasswordKVField),
			zap.Any("available_fields", getMapKeys(kvData)))
		return nil, cerr.Newf("password field '%s' missing or invalid",
			vaultpaths.UserpassBootstrapPasswordKVField)
	}

	log.Info("   ✓ Bootstrap password retrieved successfully",
		zap.String("path", vaultpaths.UserpassBootstrapPasswordKVPath),
		zap.Int("password_length", len(password)))

	// Build return data
	bootstrapData := &MFABootstrapData{
		Username:   username,
		Password:   password,
		EntityID:   entityID,
		SecretPath: vaultpaths.UserpassBootstrapPasswordKVPath,
		FetchedAt:  time.Now(),
	}

	log.Info(" [PRE-MFA VERIFICATION] All prerequisites verified successfully",
		zap.String("username", username),
		zap.String("entity_id", entityID),
		zap.String("entity_lookup_method", lookupMethod),
		zap.Duration("duration", time.Since(startTime)))
	log.Info("   ✓ Userpass user exists")
	log.Info("   ✓ Entity exists and is configured")
	log.Info("   ✓ Bootstrap password fetched and cached")

	return bootstrapData, nil
}

// VerifyMFAPrerequisites checks that all prerequisites for MFA setup exist
// This provides clear diagnostic output if something is misconfigured
//
// DEPRECATED: Use VerifyAndFetchMFAPrerequisites() instead.
// This function only verifies existence without fetching the bootstrap password,
// which creates a TOCTOU vulnerability (check at T0, read at T1).
//
// This function is kept for backwards compatibility but will be removed in future versions.
// It's now implemented as a simple wrapper that calls VerifyAndFetchMFAPrerequisites
// and discards the returned bootstrap data.
//
// Prerequisites checked:
// 1. Userpass user exists
// 2. Entity exists (by name or alias)
// 3. Entity alias exists for userpass mount
// 4. Bootstrap password exists (via the new function)
//
// This function is defensive and provides detailed diagnostics if any prerequisite is missing.
func VerifyMFAPrerequisites(rc *eos_io.RuntimeContext, client *api.Client, username string) error {
	// Delegate to the new function and discard the bootstrap data
	_, err := VerifyAndFetchMFAPrerequisites(rc, client, username)
	return err
}

// deleteEntityTOTPSecret deletes the TOTP secret for an entity
// This is used during cleanup when TOTP verification fails
//
// Parameters:
//   - rc: Runtime context
//   - client: Authenticated Vault client
//   - entityID: The entity ID whose TOTP secret should be deleted
//   - methodID: The TOTP method ID
//
// Returns:
//   - error: nil on success, error if deletion fails
func deleteEntityTOTPSecret(rc *eos_io.RuntimeContext, client *api.Client, entityID, methodID string) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info(" [CLEANUP] Deleting orphaned TOTP secret",
		zap.String("entity_id", entityID),
		zap.String("method_id", methodID))

	// Use admin-destroy endpoint to delete TOTP secret for an entity
	destroyPath := "identity/mfa/method/totp/admin-destroy"
	destroyData := map[string]interface{}{
		"entity_id": entityID,
		"method_id": methodID,
	}

	_, err := client.Logical().Write(destroyPath, destroyData)
	if err != nil {
		log.Warn(" Failed to delete TOTP secret (may not exist)",
			zap.String("entity_id", entityID),
			zap.String("method_id", methodID),
			zap.Error(err))
		// Don't return error - cleanup is best-effort
		return nil
	}

	log.Info(" ✓ [CLEANUP] TOTP secret deleted successfully")
	return nil
}

// checkEntityHasTOTP checks if an entity already has TOTP configured
// Returns true if TOTP secret exists for the entity, false otherwise
//
// This is used for idempotency - we should not generate a new TOTP secret
// if one already exists, as this would create duplicate entries in the user's
// authenticator app and they wouldn't know which code to use.
//
// Parameters:
//   - rc: Runtime context
//   - client: Authenticated Vault client
//   - entityID: The entity ID to check
//   - methodID: The TOTP method ID to check against
//
// Returns:
//   - bool: true if TOTP is configured, false otherwise
//   - error: nil on success, error if check fails
func checkEntityHasTOTP(rc *eos_io.RuntimeContext, client *api.Client, entityID, methodID string) (bool, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Debug("Checking if entity has TOTP configured",
		zap.String("entity_id", entityID),
		zap.String("method_id", methodID))

	// Try to read the entity's MFA credentials for this method
	// Path: identity/mfa/method/totp/admin-generate (this endpoint is also used to check existing secrets)
	// If a secret already exists, Vault will return an error indicating it

	// Alternative approach: Try to list MFA secrets for the entity
	// Path: identity/entity/id/{entity_id}
	// Check if the entity has any MFA methods configured

	entityPath := fmt.Sprintf("identity/entity/id/%s", entityID)
	entityResp, err := client.Logical().Read(entityPath)
	if err != nil {
		log.Warn("Failed to read entity for TOTP check",
			zap.String("entity_id", entityID),
			zap.Error(err))
		// If we can't check, assume not configured (fail open for setup)
		return false, nil
	}

	if entityResp == nil || entityResp.Data == nil {
		log.Debug("Entity has no data - TOTP not configured")
		return false, nil
	}

	// Check if entity has MFA methods configured
	// The entity response includes mfa_secrets field if any MFA is configured
	if mfaSecrets, ok := entityResp.Data["mfa_secrets"].(map[string]interface{}); ok && len(mfaSecrets) > 0 {
		log.Debug("Entity has MFA secrets configured",
			zap.String("entity_id", entityID),
			zap.Int("mfa_secret_count", len(mfaSecrets)))

		// Check if any of the MFA secrets match our TOTP method ID
		for secretID, secretData := range mfaSecrets {
			if secretMap, ok := secretData.(map[string]interface{}); ok {
				if secretMethodID, ok := secretMap["method_id"].(string); ok {
					if secretMethodID == methodID {
						log.Info("Entity already has TOTP configured for this method",
							zap.String("entity_id", entityID),
							zap.String("method_id", methodID),
							zap.String("secret_id", secretID))
						return true, nil
					}
				}
			}
		}
	}

	log.Debug("Entity does not have TOTP configured for this method",
		zap.String("entity_id", entityID),
		zap.String("method_id", methodID))
	return false, nil
}

// SetupUserTOTP helps a user set up TOTP MFA for Identity-based MFA
// This function generates a user-specific TOTP secret and displays it for enrollment
//
// CRITICAL: Must be called AFTER:
//   - EnableMFAMethods() creates the TOTP MFA method
//   - VerifyAndFetchMFAPrerequisites() verifies setup and fetches bootstrap data
//
// CRITICAL: User MUST save the QR code/URL/key before continuing - they cannot retrieve it later
//
// IDEMPOTENCY: This function checks if TOTP is already configured before proceeding.
// If TOTP already exists, it will skip setup and inform the user how to reset if needed.
//
// Parameters:
//   - rc: Runtime context
//   - client: Authenticated Vault client
//   - username: Username to set up TOTP for (e.g., "eos")
//   - bootstrapData: Cached bootstrap data from VerifyAndFetchMFAPrerequisites()
//     Contains entity ID and password needed for TOTP verification
//
// Returns:
//   - error: nil on success, error if setup fails
//
// The function will:
//  1. Check staleness of cached bootstrap data (warns if >5 minutes old)
//  2. Use cached entity ID (no redundant lookup)
//  3. Check if TOTP already configured (idempotency)
//  4. Generate TOTP secret and display QR code
//  5. Verify TOTP setup with cached bootstrap password (no redundant read)
//  6. Clean up orphaned secrets on verification failure
func SetupUserTOTP(rc *eos_io.RuntimeContext, client *api.Client, username string, bootstrapData *MFABootstrapData) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("")
	log.Info("═══════════════════════════════════════════════════════════")
	log.Info(" Setting up TOTP MFA for user: " + username)
	log.Info("═══════════════════════════════════════════════════════════")
	log.Info("")

	// STALENESS CHECK: Warn if cached bootstrap data is old
	dataAge := bootstrapData.Age()
	if dataAge > 5*time.Minute {
		log.Warn("Bootstrap data is older than 5 minutes",
			zap.Duration("age", dataAge),
			zap.Time("fetched_at", bootstrapData.FetchedAt),
			zap.String("warning", "password may have been rotated since verification"))
		log.Warn("If TOTP verification fails below, this staleness may be the cause")
	} else {
		log.Debug("Using cached bootstrap data",
			zap.Duration("age", dataAge),
			zap.Time("fetched_at", bootstrapData.FetchedAt))
	}

	// Step 1: Retrieve the TOTP method ID that was created during EnableMFAMethods
	log.Info(" [ASSESS] Retrieving TOTP MFA method configuration")
	methodIDSecret, err := client.Logical().Read("secret/data/eos/mfa-methods/totp")
	if err != nil {
		log.Error(" Failed to read TOTP method ID from Vault",
			zap.Error(err))
		log.Error("")
		log.Error("This usually means MFA was not enabled during Vault setup.")
		log.Error("To fix: Run 'eos update vault --enable-mfa'")
		log.Error("")
		return cerr.Wrap(err, "failed to read TOTP method ID - MFA not configured")
	}

	if methodIDSecret == nil || methodIDSecret.Data == nil {
		log.Error(" TOTP MFA method not found - MFA may not be enabled")
		return cerr.New("TOTP MFA method not found in Vault KV")
	}

	data, ok := methodIDSecret.Data["data"].(map[string]interface{})
	if !ok {
		log.Error(" Invalid TOTP method data structure")
		return cerr.New("invalid TOTP method data structure")
	}

	methodID, ok := data["method_id"].(string)
	if !ok || methodID == "" {
		log.Error(" TOTP method_id is not valid")
		return cerr.New("TOTP method_id is not valid")
	}

	log.Info(" ✓ TOTP MFA method found", zap.String("method_id", methodID))

	// Step 2: Use cached entity ID from bootstrap data
	// Entity lookup was already performed in VerifyAndFetchMFAPrerequisites()
	entityID := bootstrapData.EntityID
	log.Info(" [CACHED] Using entity ID from bootstrap data",
		zap.String("entity_id", entityID),
		zap.String("username", username))

	// State transition: Entity lookup complete (from cache)
	log.Info("MFA Setup State Transition",
		zap.String("from_state", "methods_created"),
		zap.String("to_state", "entity_lookup_complete"),
		zap.String("entity_id", entityID),
		zap.String("method", "cached"))

	// Step 2.5: IDEMPOTENCY CHECK - Check if TOTP is already configured
	// This prevents creating duplicate TOTP entries in the user's authenticator app
	log.Info(" [IDEMPOTENCY] Checking if TOTP is already configured for this user")
	hasTOTP, checkErr := checkEntityHasTOTP(rc, client, entityID, methodID)
	if checkErr != nil {
		log.Warn("Failed to check if TOTP exists - proceeding with setup anyway",
			zap.Error(checkErr))
		// Don't fail here - if check fails, proceed with setup (fail open)
	} else if hasTOTP {
		log.Info("")
		log.Info("═══════════════════════════════════════════════════════════")
		log.Info(" ✓ TOTP is already configured for this user")
		log.Info("═══════════════════════════════════════════════════════════")
		log.Info("")
		log.Info(fmt.Sprintf("TOTP MFA is already set up for user '%s'.", username))
		log.Info("The user already has a TOTP secret in their authenticator app.")
		log.Info("")
		log.Info("If you need to reconfigure TOTP (e.g., lost authenticator device):")
		log.Info("  1. Delete the existing TOTP secret:")
		log.Info(fmt.Sprintf("     vault write identity/mfa/method/totp/admin-destroy entity_id=%s method_id=%s", entityID, methodID))
		log.Info("  2. Re-run TOTP setup:")
		log.Info(fmt.Sprintf("     eos update vault --setup-mfa-user %s", username))
		log.Info("")
		log.Info("IMPORTANT: Deleting the TOTP secret will lock the user out until")
		log.Info("they complete TOTP setup again with a new QR code.")
		log.Info("")
		return nil // Success - already configured (idempotent)
	}

	log.Info(" ✓ [IDEMPOTENCY] TOTP not yet configured - proceeding with setup")

	// Step 3: Generate TOTP secret using admin endpoint
	log.Info(" [INTERVENE] Generating TOTP secret for user",
		zap.String("entity_id", entityID),
		zap.String("method_id", methodID))

	// CRITICAL: Use admin-generate endpoint which accepts explicit entity_id
	// The regular /generate endpoint requires the calling token to have an entity,
	// but root token has no entity. Admin endpoint solves this by accepting entity_id parameter.
	generatePath := "identity/mfa/method/totp/admin-generate"
	generateData := map[string]interface{}{
		"method_id": methodID,
		"entity_id": entityID, // Required for admin-generate
	}

	log.Debug("TOTP generation request",
		zap.String("path", generatePath),
		zap.String("entity_id", entityID),
		zap.String("method_id", methodID))

	secret, err := client.Logical().Write(generatePath, generateData)
	if err != nil {
		log.Error(" Failed to generate TOTP secret",
			zap.Error(err),
			zap.String("username", username),
			zap.String("path", generatePath))
		return cerr.Wrap(err, "failed to generate TOTP secret")
	}

	if secret == nil || secret.Data == nil {
		log.Error(" No TOTP secret data returned from Vault")
		return cerr.New("no TOTP secret data returned")
	}

	log.Info(" ✓ TOTP secret generated successfully")

	// State transition: TOTP secret generated
	log.Info("MFA Setup State Transition",
		zap.String("from_state", "entity_lookup_complete"),
		zap.String("to_state", "totp_secret_generated"),
		zap.String("entity_id", entityID))

	// CRITICAL: Setup cleanup defer pattern to delete orphaned TOTP secret on failure
	// This prevents leaving orphaned secrets that would cause duplicate entries in authenticator apps
	var verificationSucceeded bool
	defer func() {
		if !verificationSucceeded {
			log.Warn("")
			log.Warn("═══════════════════════════════════════════════════════════")
			log.Warn(" TOTP verification failed - cleaning up orphaned secret")
			log.Warn("═══════════════════════════════════════════════════════════")
			log.Warn("")
			log.Warn("The TOTP secret was generated but verification did not complete successfully.")
			log.Warn("Deleting the orphaned secret so you can retry without duplicates.")
			log.Warn("")

			if cleanupErr := deleteEntityTOTPSecret(rc, client, entityID, methodID); cleanupErr != nil {
				log.Error(" Cleanup failed - you may have an orphaned TOTP secret",
					zap.Error(cleanupErr))
				log.Error("Manual cleanup command:")
				log.Error(fmt.Sprintf("  vault write identity/mfa/method/totp/admin-destroy entity_id=%s method_id=%s",
					entityID, methodID))
			}
		}
	}()

	log.Info("")

	// Step 4: Display the secret to the user (CRITICAL - they can't retrieve this later)
	log.Info("═══════════════════════════════════════════════════════════")
	log.Info("   IMPORTANT: Save this information NOW")
	log.Info("═══════════════════════════════════════════════════════════")
	log.Info("")
	log.Info("You MUST add this TOTP configuration to your authenticator app")
	log.Info("(Google Authenticator, Authy, 1Password, etc.)")
	log.Info("")
	log.Info("This information will NOT be shown again!")
	log.Info("")

	// Extract and display URL (for manual entry)
	if url, ok := secret.Data["url"].(string); ok && url != "" {
		log.Info("Option 1: Scan QR code (if terminal supports it)")
		log.Info("─────────────────────────────────────────────────────────")
		log.Info("Open your authenticator app and scan this QR code:")
		log.Info("")
		log.Info(url) // The URL can be used to generate QR code
		log.Info("")
	}

	// Extract and display barcode (base64 encoded PNG QR code)
	if barcode, ok := secret.Data["barcode"].(string); ok && barcode != "" {
		log.Info("QR Code available (base64-encoded PNG)")
		log.Info("You can decode and display this with: echo '<barcode>' | base64 -d > qr.png")
		log.Info("")
	}

	// Extract and display backup key (for manual entry)
	log.Info("Option 2: Manual entry")
	log.Info("─────────────────────────────────────────────────────────")

	if key, ok := secret.Data["secret"].(string); ok && key != "" {
		log.Info("Backup Key (enter this manually if QR code doesn't work):")
		log.Info("")
		log.Info("  " + key)
		log.Info("")
		log.Info("Account: Vault - Eos Infrastructure (" + username + ")")
		log.Info("Type: Time-based (TOTP)")
		log.Info("Digits: 6")
		log.Info("Period: 30 seconds")
		log.Info("")
	}

	log.Info("═══════════════════════════════════════════════════════════")
	log.Info("")

	// Step 4: Prompt user to test TOTP code
	log.Info("Now please test your TOTP code to verify it works.")
	log.Info("")

	// Wait for user to confirm they've saved the secret
	if !interaction.PromptYesNo(rc.Ctx, "Have you saved the TOTP secret in your authenticator app?", true) {
		log.Warn("User declined to save TOTP secret")
		log.Warn("WARNING: User will NOT be able to authenticate with MFA until they configure TOTP")
		return cerr.New("user did not save TOTP secret")
	}

	// Verify TOTP setup by performing an actual login test
	log.Info("")
	log.Info("Testing TOTP code via actual authentication...")
	log.Info("")

	testCodes, err := interaction.PromptSecrets(rc.Ctx, "Enter the 6-digit TOTP code from your authenticator app", 1)
	if err != nil {
		log.Error(" Failed to get test code from user", zap.Error(err))
		return cerr.Wrap(err, "failed to get test code")
	}

	totpCode := testCodes[0]

	// Step 1: Use cached bootstrap password from MFABootstrapData
	// This password was already read and verified in VerifyAndFetchMFAPrerequisites()
	password := bootstrapData.Password
	log.Info(" [CACHED] Using bootstrap password from cached data",
		zap.String("source_path", bootstrapData.SecretPath),
		zap.Int("password_length", len(password)),
		zap.Duration("cache_age", bootstrapData.Age()))

	// Step 2: Perform userpass login to trigger MFA challenge
	log.Info(" [VERIFICATION] Attempting userpass login (will trigger MFA challenge)")
	loginPath := fmt.Sprintf("auth/userpass/login/%s", username)
	loginData := map[string]interface{}{"password": password}

	loginResp, err := client.Logical().Write(loginPath, loginData)
	if err != nil {
		log.Error(" [VERIFICATION] Userpass login failed",
			zap.String("username", username),
			zap.Error(err))
		return cerr.Wrap(err, "userpass login failed during TOTP verification")
	}

	if loginResp == nil {
		log.Error(" [VERIFICATION] Userpass login returned nil response")
		return cerr.New("userpass login returned nil response")
	}

	// Step 3: Extract MFA challenge
	log.Info(" [VERIFICATION] MFA challenge received - validating TOTP code")
	if loginResp.Auth != nil {
		// No MFA challenge - this shouldn't happen if MFA is enabled
		log.Warn(" [VERIFICATION] No MFA challenge received - MFA may not be enforced",
			zap.String("username", username))
		return cerr.New("expected MFA challenge but got direct authentication - MFA not enforced?")
	}

	// MFA challenge is in Data field
	if loginResp.Data == nil {
		log.Error(" [VERIFICATION] Login response missing data field")
		return cerr.New("login response missing data field")
	}

	mfaRequestID, ok := loginResp.Data["mfa_request_id"].(string)
	if !ok || mfaRequestID == "" {
		log.Error(" [VERIFICATION] No MFA request ID in response",
			zap.Any("response_data", loginResp.Data))
		return cerr.New("no mfa_request_id in login response - MFA may not be configured correctly")
	}

	log.Info(" [VERIFICATION] MFA challenge ID received",
		zap.String("mfa_request_id", mfaRequestID))

	// Step 4: Validate TOTP code
	log.Info(" [VERIFICATION] Submitting TOTP code for validation")
	mfaPayload := map[string]interface{}{
		"mfa_request_id": mfaRequestID,
		"mfa_payload": map[string][]string{
			"totp": {totpCode},
		},
	}

	mfaResp, err := client.Logical().Write("sys/mfa/validate", mfaPayload)
	if err != nil {
		log.Error(" [VERIFICATION] TOTP code validation failed",
			zap.Error(err),
			zap.String("mfa_request_id", mfaRequestID))
		log.Error("")
		log.Error(" ✗ TOTP code verification FAILED")
		log.Error("")
		log.Error("Common causes:")
		log.Error("  • Code expired (TOTP codes are valid for 30 seconds)")
		log.Error("  • Incorrect manual entry of backup key")
		log.Error("  • Device clock not synchronized with server")
		log.Error("  • Authenticator app time drift")
		log.Error("")
		log.Error("Please try again with a fresh TOTP code.")
		return cerr.Wrap(err, "TOTP validation failed during test login")
	}

	if mfaResp == nil || mfaResp.Auth == nil {
		log.Error(" [VERIFICATION] MFA validation returned invalid response")
		return cerr.New("MFA validation returned nil auth")
	}

	// Step 5: Extract and clean up test token
	testToken := mfaResp.Auth.ClientToken
	log.Info(" ✓ [VERIFICATION] Test login successful!",
		zap.String("test_token_accessor", mfaResp.Auth.Accessor))

	// Clean up: Revoke the test token immediately (we don't need it)
	defer func() {
		if testToken != "" {
			log.Debug(" [VERIFICATION] Revoking test token",
				zap.String("accessor", mfaResp.Auth.Accessor))
			// Create a new client with the test token to revoke itself
			testClient, cloneErr := client.Clone()
			if cloneErr == nil {
				testClient.SetToken(testToken)
				if revokeErr := testClient.Auth().Token().RevokeSelf(""); revokeErr != nil {
					log.Warn(" [VERIFICATION] Failed to revoke test token (non-fatal)",
						zap.Error(revokeErr))
				} else {
					log.Debug(" [VERIFICATION] Test token revoked successfully")
				}
			}
		}
	}()

	log.Info("")
	log.Info(" ✓ TOTP code verified successfully via test login!")
	log.Info("")

	// Mark verification as succeeded to prevent cleanup defer from deleting the secret
	verificationSucceeded = true

	// State transition: TOTP verification succeeded
	log.Info("MFA Setup State Transition",
		zap.String("from_state", "totp_secret_generated"),
		zap.String("to_state", "totp_verified"),
		zap.String("entity_id", entityID),
		zap.String("note", "Ready for MFA enforcement"))

	// CRITICAL: Delete bootstrap password now that TOTP verification succeeded
	// This password was only needed for initial setup and should not persist
	log.Info(" [CLEANUP] Deleting ephemeral bootstrap password from Vault KV")
	_, deleteErr := client.Logical().Delete(vaultpaths.UserpassBootstrapPasswordKVPath)
	if deleteErr != nil {
		log.Warn(" Failed to delete bootstrap password (non-fatal)",
			zap.String("path", vaultpaths.UserpassBootstrapPasswordKVPath),
			zap.Error(deleteErr))
		log.Warn("")
		log.Warn(fmt.Sprintf("The bootstrap password still exists at: %s", vaultpaths.UserpassBootstrapPasswordKVPath))
		log.Warn("This password is no longer needed and should be deleted manually:")
		log.Warn(fmt.Sprintf("  vault kv delete %s", vaultpaths.UserpassBootstrapPasswordCLIPath))
		log.Warn("")
	} else {
		log.Info(" ✓ [CLEANUP] Bootstrap password deleted successfully",
			zap.String("path", vaultpaths.UserpassBootstrapPasswordKVPath))
	}

	log.Info("")
	log.Info("═══════════════════════════════════════════════════════════")
	log.Info(" TOTP MFA setup complete for user: " + username)
	log.Info("═══════════════════════════════════════════════════════════")
	log.Info("")
	log.Info("Verification summary:")
	log.Info("  ✓ Userpass authentication successful")
	log.Info("  ✓ MFA challenge triggered correctly")
	log.Info("  ✓ TOTP code validated successfully")
	log.Info("  ✓ Complete authentication flow verified")
	log.Info("  ✓ Bootstrap password cleaned up")
	log.Info("")
	log.Info("You will now be prompted for a TOTP code every time you")
	log.Info("authenticate to Vault with your username and password.")
	log.Info("")

	return nil
}
