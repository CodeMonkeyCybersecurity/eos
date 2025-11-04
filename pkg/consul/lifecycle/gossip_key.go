package lifecycle

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/secrets"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	consulConfigPath = "/etc/consul.d/consul.hcl"
	gossipKeyPath    = "/etc/consul.d/gossip.key"
)

func loadExistingGossipKey(logger otelzap.LoggerWithCtx) string {
	if data, err := os.ReadFile(gossipKeyPath); err == nil {
		if key := strings.TrimSpace(string(data)); key != "" {
			logger.Info("Reusing gossip encryption key from cache file",
				zap.String("path", gossipKeyPath))
			return key
		}
	}

	if data, err := os.ReadFile(consulConfigPath); err == nil {
		if parsed, parseErr := config.ParseHCL(string(data)); parseErr == nil && parsed.Encrypt != "" {
			logger.Info("Reusing gossip encryption key from existing configuration",
				zap.String("path", consulConfigPath))
			return parsed.Encrypt
		}
	}
	return ""
}

func persistGossipKey(logger otelzap.LoggerWithCtx, key string) error {
	if err := os.WriteFile(gossipKeyPath, []byte(key+"\n"), 0o600); err != nil {
		return fmt.Errorf("failed to persist gossip key: %w", err)
	}

	if err := os.Chmod(gossipKeyPath, 0o600); err != nil {
		logger.Warn("Failed to set gossip key permissions",
			zap.String("path", gossipKeyPath),
			zap.Error(err))
	}

	if err := chownConsul(gossipKeyPath); err != nil {
		logger.Warn("Failed to set gossip key ownership",
			zap.String("path", gossipKeyPath),
			zap.Error(err))
	}

	return nil
}

func chownConsul(path string) error {
	owner, err := user.Lookup("consul")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(owner.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(owner.Gid)
	if err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}

func ensureGossipKey(logger otelzap.LoggerWithCtx) (string, error) {
	if key := loadExistingGossipKey(logger); key != "" {
		return key, nil
	}

	key, err := secrets.GenerateGossipKey()
	if err != nil {
		return "", fmt.Errorf("failed to generate gossip encryption key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(gossipKeyPath), 0o755); err != nil {
		logger.Warn("Failed to ensure directory for gossip key",
			zap.Error(err),
			zap.String("path", gossipKeyPath))
	} else if err := persistGossipKey(logger, key); err != nil {
		logger.Warn("Failed to persist gossip key to disk", zap.Error(err))
	}

	logger.Info("Generated new gossip encryption key",
		zap.String("path", gossipKeyPath))
	return key, nil
}
