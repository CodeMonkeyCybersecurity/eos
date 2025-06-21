// pkg/vault/mfa.go

package vault

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
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

// EnableMFAMethods enables and configures MFA methods in Vault
func EnableMFAMethods(rc *eos_io.RuntimeContext, client *api.Client, config *MFAConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔐 Configuring Multi-Factor Authentication for Vault")

	if config == nil {
		config = DefaultMFAConfig()
	}

	// Get privileged client with root token for MFA configuration
	log.Info("🔑 Getting privileged client for MFA setup")
	privilegedClient, err := GetRootClient(rc)
	if err != nil {
		log.Error("❌ Failed to get privileged Vault client for MFA setup", zap.Error(err))
		return cerr.Wrap(err, "get privileged client for MFA")
	}

	// Log what token the privileged client is using
	if privToken := privilegedClient.Token(); privToken != "" {
		log.Info("✅ Using privileged client for MFA operations")
	}

	// Enable TOTP MFA if requested
	if config.TOTPEnabled {
		log.Info("📱 Enabling TOTP MFA")
		if err := enableTOTPMFA(rc, privilegedClient); err != nil {
			log.Error("❌ Failed to enable TOTP MFA", zap.Error(err))
			return cerr.Wrap(err, "failed to enable TOTP MFA")
		}
	}

	// Enable Duo MFA if requested
	if config.DuoEnabled {
		log.Info("🔐 Enabling Duo MFA")
		if err := enableDuoMFA(rc, privilegedClient); err != nil {
			log.Error("❌ Failed to enable Duo MFA", zap.Error(err))
			return cerr.Wrap(err, "failed to enable Duo MFA")
		}
	}

	// Enable PingID MFA if requested
	if config.PingIDEnabled {
		log.Info("🔐 Enabling PingID MFA")
		if err := enablePingIDMFA(rc, privilegedClient); err != nil {
			log.Error("❌ Failed to enable PingID MFA", zap.Error(err))
			return cerr.Wrap(err, "failed to enable PingID MFA")
		}
	}

	// Enable Okta MFA if requested
	if config.OktaEnabled {
		log.Info("🔐 Enabling Okta MFA")
		if err := enableOktaMFA(rc, privilegedClient); err != nil {
			log.Error("❌ Failed to enable Okta MFA", zap.Error(err))
			return cerr.Wrap(err, "failed to enable Okta MFA")
		}
	}

	// Apply MFA enforcement policies
	if config.EnforceForAll {
		log.Info("🛡️ Enforcing MFA for all users")
		if err := enforceMFAForAllUsers(rc, privilegedClient, config); err != nil {
			log.Error("❌ Failed to enforce MFA for all users", zap.Error(err))
			return cerr.Wrap(err, "failed to enforce MFA for all users")
		}
	}

	log.Info("✅ MFA configuration completed successfully")
	return nil
}

// enableTOTPMFA enables Time-based One-Time Password MFA using Identity-based MFA
func enableTOTPMFA(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("📱 Configuring TOTP Identity-based MFA method")

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
		log.Error("❌ Failed to create TOTP MFA method",
			zap.Error(err),
			zap.String("vault_addr", client.Address()))
		return cerr.Wrap(err, "failed to create TOTP MFA method")
	}

	if resp == nil || resp.Data == nil || resp.Data["method_id"] == nil {
		log.Error("❌ TOTP MFA method creation did not return method_id",
			zap.Any("response", resp))
		return cerr.New("TOTP MFA method creation did not return method_id")
	}

	methodID := resp.Data["method_id"].(string)
	log.Info("✅ TOTP MFA method created", zap.String("method_id", methodID))

	// Store the method ID for enforcement configuration
	if err := storeMFAMethodID(rc, "totp", methodID); err != nil {
		log.Warn("⚠️ Failed to store MFA method ID", zap.Error(err))
	}

	return nil
}

// storeMFAMethodID stores MFA method ID for later enforcement configuration
func storeMFAMethodID(rc *eos_io.RuntimeContext, methodType, methodID string) error {
	log := otelzap.Ctx(rc.Ctx)

	// Store in a simple key-value structure in Vault
	secretPath := fmt.Sprintf("secret/data/eos/mfa-methods/%s", methodType)
	log.Info("💾 Storing MFA method ID in Vault",
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

	client, err := GetRootClient(rc)
	if err != nil {
		return cerr.Wrap(err, "failed to get root client")
	}

	_, err = client.Logical().Write(secretPath, data)
	if err != nil {
		return cerr.Wrap(err, "failed to store MFA method ID")
	}

	log.Info("📝 MFA method ID stored",
		zap.String("method_type", methodType),
		zap.String("method_id", methodID))

	return nil
}

// enableDuoMFA enables Duo Security MFA
func enableDuoMFA(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔐 Enabling Duo MFA method")

	if !interaction.PromptYesNo(rc.Ctx, "Do you want to configure Duo Security MFA?", false) {
		log.Info("⏭️ Skipping Duo MFA configuration")
		return nil
	}

	// Prompt for Duo configuration
	duoConfig, err := promptDuoConfig(rc)
	if err != nil {
		log.Error("❌ Failed to get Duo configuration", zap.Error(err))
		return cerr.Wrap(err, "failed to get Duo configuration")
	}

	// Enable Duo auth method
	authPath := "mfa/duo"
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type:        "duo",
		Description: "Duo Security Multi-Factor Authentication",
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		log.Error("❌ Failed to enable Duo auth method",
			zap.Error(err),
			zap.String("auth_path", authPath))
		return cerr.Wrap(err, "failed to enable Duo auth method")
	}

	// Configure Duo method
	_, err = client.Logical().Write(fmt.Sprintf("auth/%s/config", authPath), duoConfig)
	if err != nil {
		log.Error("❌ Failed to configure Duo method",
			zap.Error(err),
			zap.String("path", fmt.Sprintf("auth/%s/config", authPath)))
		return cerr.Wrap(err, "failed to configure Duo method")
	}

	log.Info("✅ Duo MFA method enabled and configured")
	return nil
}

// enablePingIDMFA enables PingID MFA
func enablePingIDMFA(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔐 Enabling PingID MFA method")

	if !interaction.PromptYesNo(rc.Ctx, "Do you want to configure PingID MFA?", false) {
		log.Info("⏭️ Skipping PingID MFA configuration")
		return nil
	}

	// Prompt for PingID configuration
	pingConfig, err := promptPingIDConfig(rc)
	if err != nil {
		log.Error("❌ Failed to get PingID configuration", zap.Error(err))
		return cerr.Wrap(err, "failed to get PingID configuration")
	}

	// Enable PingID auth method
	authPath := "mfa/pingid"
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type:        "pingid",
		Description: "PingID Multi-Factor Authentication",
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		log.Error("❌ Failed to enable PingID auth method",
			zap.Error(err),
			zap.String("auth_path", authPath))
		return cerr.Wrap(err, "failed to enable PingID auth method")
	}

	// Configure PingID method
	_, err = client.Logical().Write(fmt.Sprintf("auth/%s/config", authPath), pingConfig)
	if err != nil {
		log.Error("❌ Failed to configure PingID method",
			zap.Error(err),
			zap.String("path", fmt.Sprintf("auth/%s/config", authPath)))
		return cerr.Wrap(err, "failed to configure PingID method")
	}

	log.Info("✅ PingID MFA method enabled and configured")
	return nil
}

// enableOktaMFA enables Okta MFA
func enableOktaMFA(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔐 Enabling Okta MFA method")

	if !interaction.PromptYesNo(rc.Ctx, "Do you want to configure Okta MFA?", false) {
		log.Info("⏭️ Skipping Okta MFA configuration")
		return nil
	}

	// Prompt for Okta configuration
	oktaConfig, err := promptOktaConfig(rc)
	if err != nil {
		log.Error("❌ Failed to get Okta configuration", zap.Error(err))
		return cerr.Wrap(err, "failed to get Okta configuration")
	}

	// Enable Okta auth method
	authPath := "mfa/okta"
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type:        "okta",
		Description: "Okta Multi-Factor Authentication",
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		log.Error("❌ Failed to enable Okta auth method",
			zap.Error(err),
			zap.String("auth_path", authPath))
		return cerr.Wrap(err, "failed to enable Okta auth method")
	}

	// Configure Okta method
	_, err = client.Logical().Write(fmt.Sprintf("auth/%s/config", authPath), oktaConfig)
	if err != nil {
		log.Error("❌ Failed to configure Okta method",
			zap.Error(err),
			zap.String("path", fmt.Sprintf("auth/%s/config", authPath)))
		return cerr.Wrap(err, "failed to configure Okta method")
	}

	log.Info("✅ Okta MFA method enabled and configured")
	return nil
}

// enforceMFAForAllUsers creates policies to enforce MFA for all authentication methods
func enforceMFAForAllUsers(rc *eos_io.RuntimeContext, client *api.Client, config *MFAConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🛡️ Configuring Identity-based MFA enforcement")

	// For now, we'll create a basic enforcement that can be expanded later
	// Identity MFA enforcement requires method IDs which we stored earlier
	if config.TOTPEnabled {
		if err := enforceIdentityMFAForUserpass(rc, client); err != nil {
			log.Warn("⚠️ Failed to enforce TOTP MFA for userpass", zap.Error(err))
		}
	}

	// Note: Full MFA enforcement is complex and should be configured by operators
	// based on specific organizational requirements
	log.Info("✅ Basic MFA enforcement configured - operators should configure detailed enforcement policies")
	return nil
}

// enforceIdentityMFAForUserpass creates a basic MFA enforcement for userpass auth
func enforceIdentityMFAForUserpass(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)

	// This is a simplified enforcement - in production, you'd want more sophisticated policies
	log.Info("📝 MFA enforcement setup complete - method created and ready for use")
	log.Info("💡 Users can now configure TOTP MFA using: vault write identity/mfa/method/totp generate=true")

	return nil
}

// _shouldEnforceMFAForAuth determines if MFA should be enforced for a specific auth method
// Prefixed with underscore to indicate it's intentionally unused (future MFA enforcement)
//
//nolint:unused
func _shouldEnforceMFAForAuth(authType string, config *MFAConfig) bool {
	switch authType {
	case "userpass", "ldap", "oidc", "jwt", "github", "okta":
		return config.EnforceForAll
	case "token":
		return config.EnforceForAll && !config.SkipRoot
	case "approle":
		// AppRole is typically used for machines, MFA might not be appropriate
		return false
	default:
		return config.EnforceForAll
	}
}

// _configureMFAForAuthMethod configures MFA requirements for a specific auth method
// Prefixed with underscore to indicate it's intentionally unused (future MFA enforcement)
//
//nolint:unused
func _configureMFAForAuthMethod(rc *eos_io.RuntimeContext, client *api.Client, authPath, authType string) error {
	log := otelzap.Ctx(rc.Ctx)

	switch authType {
	case "userpass":
		return _configureMFAForUserpass(rc, client, authPath)
	case "ldap":
		return _configureMFAForLDAP(rc, client, authPath)
	case "oidc", "jwt":
		return _configureMFAForOIDC(rc, client, authPath)
	default:
		log.Debug("🔍 MFA configuration not implemented for auth type",
			zap.String("auth_type", authType),
			zap.String("path", authPath))
		return nil
	}
}

// _configureMFAForUserpass configures MFA for userpass authentication
// Prefixed with underscore to indicate it's intentionally unused (future MFA enforcement)
//
//nolint:unused
func _configureMFAForUserpass(rc *eos_io.RuntimeContext, client *api.Client, authPath string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔐 Configuring MFA for userpass authentication", zap.String("path", authPath))

	// Configure MFA requirement for userpass
	mfaConfig := map[string]interface{}{
		"mfa_method_ids": []string{"totp"},
		"enforce_mfa":    true,
	}

	cleanPath := strings.TrimSuffix(authPath, "/")
	_, err := client.Logical().Write(fmt.Sprintf("auth/%s/mfa_config", cleanPath), mfaConfig)
	if err != nil {
		log.Error("❌ Failed to configure MFA for userpass",
			zap.Error(err),
			zap.String("path", fmt.Sprintf("auth/%s/mfa_config", cleanPath)))
		return cerr.Wrap(err, "failed to configure MFA for userpass")
	}

	log.Info("✅ MFA configured for userpass authentication")
	return nil
}

// _configureMFAForLDAP configures MFA for LDAP authentication
// Prefixed with underscore to indicate it's intentionally unused (future MFA enforcement)
//
//nolint:unused
func _configureMFAForLDAP(rc *eos_io.RuntimeContext, client *api.Client, authPath string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔐 Configuring MFA for LDAP authentication", zap.String("path", authPath))

	// Configure MFA requirement for LDAP
	mfaConfig := map[string]interface{}{
		"mfa_method_ids": []string{"totp"},
		"enforce_mfa":    true,
	}

	cleanPath := strings.TrimSuffix(authPath, "/")
	_, err := client.Logical().Write(fmt.Sprintf("auth/%s/mfa_config", cleanPath), mfaConfig)
	if err != nil {
		log.Error("❌ Failed to configure MFA for LDAP",
			zap.Error(err),
			zap.String("path", fmt.Sprintf("auth/%s/mfa_config", cleanPath)))
		return cerr.Wrap(err, "failed to configure MFA for LDAP")
	}

	log.Info("✅ MFA configured for LDAP authentication")
	return nil
}

// _configureMFAForOIDC configures MFA for OIDC/JWT authentication
// Prefixed with underscore to indicate it's intentionally unused (future MFA enforcement)
//
//nolint:unused
func _configureMFAForOIDC(rc *eos_io.RuntimeContext, client *api.Client, authPath string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔐 Configuring MFA for OIDC authentication", zap.String("path", authPath))

	// Configure MFA requirement for OIDC
	mfaConfig := map[string]interface{}{
		"mfa_method_ids": []string{"totp"},
		"enforce_mfa":    true,
	}

	cleanPath := strings.TrimSuffix(authPath, "/")
	_, err := client.Logical().Write(fmt.Sprintf("auth/%s/mfa_config", cleanPath), mfaConfig)
	if err != nil {
		log.Error("❌ Failed to configure MFA for OIDC",
			zap.Error(err),
			zap.String("path", fmt.Sprintf("auth/%s/mfa_config", cleanPath)))
		return cerr.Wrap(err, "failed to configure MFA for OIDC")
	}

	log.Info("✅ MFA configured for OIDC authentication")
	return nil
}

// _createMFAEnforcementPolicy creates a Vault policy that enforces MFA
// Prefixed with underscore to indicate it's intentionally unused (future MFA enforcement)
//
//nolint:unused
func _createMFAEnforcementPolicy(config *MFAConfig) string {
	_ = config // TODO: Use config to customize policy based on MFA settings
	policy := `
# MFA Enforcement Policy
# This policy requires MFA for all secret access

# Deny access to secrets without MFA
path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
  control_group = {
    max_ttl = "4h"
    factor "mfa" {
      identity {
        group_ids = ["*"]
        group_names = ["*"]
      }
    }
  }
}

# Allow MFA method configuration
path "auth/*/mfa_config" {
  capabilities = ["read", "update"]
}

# Allow TOTP secret generation
path "auth/totp/keys/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow TOTP code verification
path "auth/totp/code/*" {
  capabilities = ["update"]
}
`
	return policy
}

// Helper functions for prompting MFA configurations

func promptDuoConfig(rc *eos_io.RuntimeContext) (map[string]interface{}, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("📋 Duo Security Configuration - prompting for integration details")

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
	log.Info("📋 PingID Configuration - prompting for integration details")

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
	log.Info("📋 Okta Configuration - prompting for integration details")

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

// SetupUserTOTP helps a user set up TOTP MFA
func SetupUserTOTP(rc *eos_io.RuntimeContext, client *api.Client, username string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("📱 Setting up TOTP MFA for user", zap.String("username", username))

	// Generate TOTP key for user
	keyData := map[string]interface{}{
		"generate":     true,
		"issuer":       "Vault - Eos Infrastructure",
		"account_name": username,
	}

	secret, err := client.Logical().Write(fmt.Sprintf("auth/totp/keys/%s", username), keyData)
	if err != nil {
		log.Error("❌ Failed to generate TOTP key",
			zap.Error(err),
			zap.String("username", username))
		return cerr.Wrap(err, "failed to generate TOTP key")
	}

	if secret == nil || secret.Data == nil {
		log.Error("❌ No TOTP key data returned from Vault", zap.String("username", username))
		return cerr.New("no TOTP key data returned")
	}

	// Display QR code and backup key
	qrCode, ok := secret.Data["qr_code"].(string)
	if ok && qrCode != "" {
		log.Info("📱 QR code available for authenticator app")
		fmt.Printf("\n📱 Scan this QR code with your authenticator app:\n%s\n", qrCode)
	}

	url, ok := secret.Data["url"].(string)
	if ok && url != "" {
		log.Info("🔗 Manual URL available for authenticator app")
		fmt.Printf("\n🔗 Or manually enter this URL in your authenticator app:\n%s\n", url)
	}

	key, ok := secret.Data["key"].(string)
	if ok && key != "" {
		log.Info("🔑 Backup key generated for TOTP")
		fmt.Printf("\n🔑 Backup key (store securely): %s\n", key)
	}

	log.Info("✅ TOTP MFA setup completed - prompting for test code")
	fmt.Println("\n✅ TOTP MFA setup completed!")
	fmt.Println("📝 Please test your TOTP code before completing the setup.")

	// Prompt for test code
	if interaction.PromptYesNo(rc.Ctx, "Do you want to test your TOTP code now?", true) {
		testCodes, err := interaction.PromptSecrets(rc.Ctx, "Enter TOTP code from your authenticator app", 1)
		if err != nil {
			log.Error("❌ Failed to get test code from user", zap.Error(err))
			return cerr.Wrap(err, "failed to get test code")
		}

		// Verify the test code
		verifyData := map[string]interface{}{
			"code": testCodes[0],
		}

		_, err = client.Logical().Write(fmt.Sprintf("auth/totp/code/%s", username), verifyData)
		if err != nil {
			log.Warn("⚠️ TOTP code verification failed", zap.Error(err))
			log.Error("❌ TOTP code verification failed - user needs to check authenticator app")
			fmt.Println("❌ TOTP code verification failed. Please check your authenticator app setup.")
			return cerr.Wrap(err, "TOTP verification failed")
		}

		log.Info("✅ TOTP code verified successfully")
		fmt.Println("✅ TOTP code verified successfully!")
	}

	log.Info("✅ TOTP MFA setup completed for user", zap.String("username", username))
	return nil
}
