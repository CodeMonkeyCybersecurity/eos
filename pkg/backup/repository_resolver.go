package backup

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// ResolveRepositoryName resolves an explicit repository or falls back to the configured default.
// It also validates that the resolved repository exists in configuration.
func ResolveRepositoryName(rc *eos_io.RuntimeContext, requested string) (string, error) {
	config, err := LoadConfig(rc)
	if err != nil {
		return "", fmt.Errorf("loading configuration: %w", err)
	}

	return ResolveRepositoryNameFromConfig(config, requested)
}

// ResolveRepositoryNameFromConfig resolves an explicit repository or default repository from config.
func ResolveRepositoryNameFromConfig(config *Config, requested string) (string, error) {
	if config == nil {
		recordRepositoryResolution("config_nil", false)
		return "", fmt.Errorf("configuration is required")
	}

	repoName := strings.TrimSpace(requested)
	if repoName == "" {
		repoName = strings.TrimSpace(config.DefaultRepository)
		if repoName == "" {
			recordRepositoryResolution("default", false)
			return "", ErrRepositoryNotSpecified
		}
	}

	if _, exists := config.Repositories[repoName]; !exists {
		recordRepositoryResolution("explicit", false)
		return "", fmt.Errorf("repository %q not found in configuration", repoName)
	}
	if strings.TrimSpace(requested) == "" {
		recordRepositoryResolution("default", true)
	} else {
		recordRepositoryResolution("explicit", true)
	}

	return repoName, nil
}
