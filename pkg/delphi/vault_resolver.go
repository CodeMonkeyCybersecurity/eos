package delphi

import (
	"errors"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"go.uber.org/zap"
)

func ResolveConfig(log *zap.Logger) (*Config, error) {
	// 1. Try Vault
	cfg, err := ReadConfig(log)
	if err == nil && cfg.IsValid() {
		return cfg, nil
	}

	// 2. Try disk fallback
	cfg, err = ReadConfig(log) // fixed arg
	if err == nil && cfg.IsValid() {
		log.Info("Loaded Delphi config from disk fallback")
		return cfg, nil
	}

	// 3. Prompt interactively
	cfg = PromptDelphiConfig(log)

	ok, err := interaction.ResolveObject(cfg, log)
	if err != nil {
		log.Warn("Confirmation failed", zap.Error(err))
		return nil, err
	}
	if !ok {
		return nil, errors.New("user aborted config confirmation")
	}

	// 5. Save and return
	_ = WriteConfig(cfg, log)
	return cfg, nil
}
