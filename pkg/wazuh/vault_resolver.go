package wazuh

import (
	"errors"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func ResolveConfig(rc *eos_io.RuntimeContext) (*Config, error) {
	// 1. Try Vault
	cfg, err := ReadConfig(rc)
	if err == nil && cfg.IsValid() {
		return cfg, nil
	}

	// 2. Try disk fallback
	cfg, err = ReadConfig(rc) // fixed arg
	if err == nil && cfg.IsValid() {
		otelzap.Ctx(rc.Ctx).Info("Loaded Wazuh config from disk fallback")
		return cfg, nil
	}

	// 3. Prompt interactively
	cfg = PromptWazuhConfig(rc)

	ok, err := interaction.ResolveObject(rc, cfg)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Confirmation failed", zap.Error(err))
		return nil, err
	}
	if !ok {
		return nil, errors.New("user aborted config confirmation")
	}

	// 5. Save and return
	_ = WriteConfig(rc, cfg)
	return cfg, nil
}
