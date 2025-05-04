// pkg/vault/phase7_ver_root_token


package vault

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// PhasePromptAndVerRootToken runs a fallback auth cascade and sets the token.
func PhasePromptAndVerRootToken(client *api.Client) error {
	zap.L().Info("🔑 [Phase 7] Starting Vault authentication fallback cascade")

	// 1. Try agent token
	if token, err := tryAgentToken(client); err == nil && verifyToken(client, token) {
		SetVaultToken(client, token)
		zap.L().Info("✅ Authenticated via agent token")
		return nil
	} else {
		zap.L().Warn("⚠️ Agent token failed", zap.Error(err))
	}

	// 2. Try AppRole
	if token, err := tryAppRole(client); err == nil && verifyToken(client, token) {
		SetVaultToken(client, token)
		zap.L().Info("✅ Authenticated via AppRole")
		return nil
	} else {
		zap.L().Warn("⚠️ AppRole auth failed", zap.Error(err))
	}

	// 3. Try reading root token from init file
	if token, err := tryInitFileRootToken(client); err == nil && verifyToken(client, token) {
		SetVaultToken(client, token)
		zap.L().Info("✅ Authenticated via init file root token")
		return nil
	} else {
		zap.L().Warn("⚠️ Init file root token auth failed", zap.Error(err))
	}

	// 4. Prompt user for root token
	token, err := promptRootToken(client)
	if err != nil {
		return fmt.Errorf("prompt root token: %w", err)
	}
	if err := VerifyRootToken(client, token); err != nil {
		return fmt.Errorf("validate root token: %w", err)
	}
	SetVaultToken(client, token)
	zap.L().Info("✅ Root token validated and applied")

	return nil
}

// recoverVaultHealth handles unseal or init if Vault is sealed or uninitialized.
func recoverVaultHealth(client *api.Client) error {
	status, err := client.Sys().Health()
	if err != nil {
		return fmt.Errorf("vault health API call failed: %w", err)
	}

	switch {
	case !status.Initialized:
		zap.L().Info("💥 Vault uninitialized — running init + unseal flow")
		_, err := UnsealVault()
		return err
	case status.Sealed:
		zap.L().Info("🔒 Vault sealed — attempting fallback unseal")
		return MustUnseal(client)
	default:
		return fmt.Errorf("unexpected vault state: initialized=%v sealed=%v", status.Initialized, status.Sealed)
	}
}
