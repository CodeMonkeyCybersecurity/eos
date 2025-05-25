package delphi

import (
	"context"
	"errors"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"go.uber.org/zap"
)

func ResolveConfig(ctx context.Context) (*Config, error) {
	// 1. Try Vault
	cfg, err := ReadConfig(ctx)
	if err == nil && cfg.IsValid() {
		return cfg, nil
	}

	// 2. Try disk fallback
	cfg, err = ReadConfig(ctx) // fixed arg
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
	_ = WriteConfig(ctx, cfg)
	return cfg, nil
}
