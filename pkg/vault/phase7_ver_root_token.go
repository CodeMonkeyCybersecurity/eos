// pkg/vault/phase7_ver_root_token

package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PhasePromptAndVerRootToken verifies the root token that was set by Phase 6.
//
// CRITICAL: This function expects the client to already have a token set by Phase 6 (UnsealVault).
// Phase 6 caches the root-authenticated client, so we should NOT try to re-authenticate here.
//
// During initial setup:
//   - Phase 6 already set root token from vault_init.json
//   - This phase just verifies that token is valid
//   - Agent/AppRole don't exist yet (Phase 10b/14 haven't run)
//
// If token is missing (shouldn't happen), fall back to authentication cascade.
func PhasePromptAndVerRootToken(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)

	// CRITICAL P0 FIX: Check if client already has a token from Phase 6
	// This prevents the 30s wait for agent token that doesn't exist yet
	if existingToken := client.Token(); existingToken != "" {
		logger.Info(" [Phase 7] Client already has token from Phase 6, verifying...")

		if VerifyToken(rc, client, existingToken) {
			logger.Info(" [Phase 7] Existing token verified successfully (from Phase 6)")
			return nil
		}

		logger.Warn(" [Phase 7] Existing token failed verification, will try fallback auth",
			zap.String("reason", "token may be expired or invalid"))
	} else {
		logger.Warn(" [Phase 7] No existing token found (unexpected), will try fallback auth",
			zap.String("note", "Phase 6 should have set the token"))
	}

	// Fallback authentication cascade (should only happen if Phase 6 failed)
	logger.Info(" [Phase 7] Starting fallback authentication cascade")

	// 1. Try agent token (will fail during initial setup - agent doesn't exist yet)
	if token, err := readTokenFile(rc, shared.AgentToken)(client); err == nil && VerifyToken(rc, client, token) {
		SetVaultToken(rc, client, token)
		logger.Info(" Authenticated via agent token")
		return nil
	} else {
		logger.Debug("Agent token not available (expected during initial setup)", zap.Error(err))
	}

	// 2. Try AppRole (will fail during initial setup - AppRole doesn't exist yet)
	if token, err := tryAppRole(rc, client); err == nil && VerifyToken(rc, client, token) {
		SetVaultToken(rc, client, token)
		logger.Info(" Authenticated via AppRole")
		return nil
	} else {
		logger.Debug("AppRole auth not available (expected during initial setup)", zap.Error(err))
	}

	// 3. Try reading root token from init file (this should work)
	if token, err := tryRootToken(rc, client); err == nil && VerifyToken(rc, client, token) {
		SetVaultToken(rc, client, token)
		logger.Info(" Authenticated via init file root token")
		return nil
	} else {
		logger.Warn("Init file root token auth failed", zap.Error(err))
	}

	// 4. Last resort: Prompt user for root token
	logger.Warn(" All automatic authentication methods failed, prompting user")
	token, err := promptRootTokenWrapper(rc)
	if err != nil {
		return fmt.Errorf("prompt root token: %w", err)
	}
	if err := VerifyRootToken(rc, client, token); err != nil {
		return fmt.Errorf("validate root token: %w", err)
	}
	SetVaultToken(rc, client, token)
	logger.Info(" Root token validated and applied")

	return nil
}

// recoverVaultHealth handles unseal or init if Vault is sealed or uninitialized.
func recoverVaultHealth(rc *eos_io.RuntimeContext, client *api.Client) error {
	status, err := client.Sys().Health()
	if err != nil {
		return fmt.Errorf("vault health API call failed: %w", err)
	}

	switch {
	case !status.Initialized:
		otelzap.Ctx(rc.Ctx).Info(" Vault uninitialized — running init + unseal flow")
		_, err := UnsealVault(rc)
		return err
	case status.Sealed:
		otelzap.Ctx(rc.Ctx).Info(" Vault sealed — attempting fallback unseal")
		return MustUnseal(rc, client)
	default:
		return fmt.Errorf("unexpected vault state: initialized=%v sealed=%v", status.Initialized, status.Sealed)
	}
}

func promptRootTokenWrapper(rc *eos_io.RuntimeContext) (string, error) {
	initRes, err := LoadOrPromptInitResult(rc)
	if err != nil {
		return "", fmt.Errorf("prompt root token failed: %w", err)
	}
	if strings.TrimSpace(initRes.RootToken) == "" {
		return "", fmt.Errorf("root token is missing in init result")
	}
	return initRes.RootToken, nil
}
