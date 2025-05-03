package delphi

import (
	"errors"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"go.uber.org/zap"
)

func ResolveConfig() (*Config, error) {
	// 1. Try Vault
	cfg, err := ReadConfig()
	if err == nil && cfg.IsValid() {
		return cfg, nil
	}

	// 2. Try disk fallback
	cfg, err = ReadConfig() // fixed arg
	if err == nil && cfg.IsValid() {
		zap.L().Info("Loaded Delphi config from disk fallback")
		return cfg, nil
	}

	// 3. Prompt interactively
	cfg = PromptDelphiConfig()

	ok, err := interaction.ResolveObject(cfg)
	if err != nil {
		zap.L().Warn("Confirmation failed", zap.Error(err))
		return nil, err
	}
	if !ok {
		return nil, errors.New("user aborted config confirmation")
	}

	// 5. Save and return
	_ = WriteConfig(cfg)
	return cfg, nil
}
