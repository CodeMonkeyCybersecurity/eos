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

// PhasePromptAndVerRootToken runs a fallback auth cascade and sets the token.
func PhasePromptAndVerRootToken(rc *eos_io.RuntimeContext, client *api.Client) error {
	otelzap.Ctx(rc.Ctx).Info("🔑 [Phase 7] Starting Vault authentication fallback cascade")

	// 1. Try agent token
	if token, err := readTokenFile(rc, shared.AgentToken)(client); err == nil && VerifyToken(rc, client, token) {
		SetVaultToken(rc, client, token)
		otelzap.Ctx(rc.Ctx).Info("✅ Authenticated via agent token")
		return nil
	} else {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ Agent token failed", zap.Error(err))
	}

	// 2. Try AppRole
	if token, err := tryAppRole(rc, client); err == nil && VerifyToken(rc, client, token) {
		SetVaultToken(rc, client, token)
		otelzap.Ctx(rc.Ctx).Info("✅ Authenticated via AppRole")
		return nil
	} else {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ AppRole auth failed", zap.Error(err))
	}

	// 3. Try reading root token from init file
	if token, err := tryRootToken(rc, client); err == nil && VerifyToken(rc, client, token) {
		SetVaultToken(rc, client, token)
		otelzap.Ctx(rc.Ctx).Info("✅ Authenticated via init file root token")
		return nil
	} else {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ Init file root token auth failed", zap.Error(err))
	}

	// 4. Prompt user for root token
	token, err := promptRootTokenWrapper(rc)
	if err != nil {
		return fmt.Errorf("prompt root token: %w", err)
	}
	if err := VerifyRootToken(rc, client, token); err != nil {
		return fmt.Errorf("validate root token: %w", err)
	}
	SetVaultToken(rc, client, token)
	otelzap.Ctx(rc.Ctx).Info("✅ Root token validated and applied")

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
		otelzap.Ctx(rc.Ctx).Info("💥 Vault uninitialized — running init + unseal flow")
		_, err := UnsealVault(rc)
		return err
	case status.Sealed:
		otelzap.Ctx(rc.Ctx).Info("🔒 Vault sealed — attempting fallback unseal")
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
