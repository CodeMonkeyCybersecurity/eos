package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var errPasswordWizardSkipped = errors.New("password wizard skipped (non-interactive)")

// runPasswordWizard launches an interactive prompt to capture and persist the restic password.
func (c *Client) runPasswordWizard(localPasswordPath, secretsPasswordPath string, envPaths []string) (string, error) {
	logger := otelzap.Ctx(c.rc.Ctx)

	if !interaction.IsTTY() {
		return "", errPasswordWizardSkipped
	}

	logger.Info("terminal prompt:", zap.String("output",
		"⚠ Restic password not found. Starting interactive credential setup..."))
	logger.Info("terminal prompt:", zap.String("output",
		"The password will be stored securely for future eos backup runs."))

	const maxAttempts = 3

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		password, err := interaction.PromptSecret("Restic repository password")
		if err != nil {
			return "", fmt.Errorf("capturing password: %w", err)
		}

		confirm, err := interaction.PromptSecret("Confirm password")
		if err != nil {
			return "", fmt.Errorf("confirming password: %w", err)
		}

		if password != confirm {
			logger.Info("terminal prompt:", zap.String("output",
				"Passwords did not match. Please try again."))
			continue
		}

		if err := c.persistRepositoryPassword(password, localPasswordPath, secretsPasswordPath, envPaths); err != nil {
			return "", err
		}

		logger.Info("terminal prompt:", zap.String("output",
			"✓ Restic password saved."))
		return password, nil
	}

	return "", fmt.Errorf("password confirmation failed after %d attempts", maxAttempts)
}

func (c *Client) persistRepositoryPassword(password, localPasswordPath, secretsPasswordPath string, envPaths []string) error {
	logger := otelzap.Ctx(c.rc.Ctx)

	var (
		passwordFilePath string
		fileWritten      bool
		envWritten       bool
	)

	// Attempt to create/update repository-local password file (preferred when repository URL is local path).
	if filepath.IsAbs(localPasswordPath) {
		if err := writePasswordFile(localPasswordPath, password); err != nil {
			logger.Warn("Failed to write repository password file",
				zap.String("path", localPasswordPath),
				zap.Error(err))
		} else {
			passwordFilePath = localPasswordPath
			fileWritten = true
			logger.Info("terminal prompt:", zap.String("output",
				fmt.Sprintf("✓ Stored password file at %s", localPasswordPath)))
		}
	} else {
		logger.Debug("Skipping repository-local password file (path not absolute)",
			zap.String("path", localPasswordPath))
	}

	// Always attempt to store fallback password file in secrets directory.
	if err := writePasswordFile(secretsPasswordPath, password); err != nil {
		logger.Warn("Failed to write secrets password file",
			zap.String("path", secretsPasswordPath),
			zap.Error(err))
	} else {
		if passwordFilePath == "" {
			passwordFilePath = secretsPasswordPath
		}
		fileWritten = true
		logger.Info("terminal prompt:", zap.String("output",
			fmt.Sprintf("✓ Stored fallback password file at %s", secretsPasswordPath)))
	}

	envUpdates := map[string]string{
		"RESTIC_PASSWORD": password,
	}
	if passwordFilePath != "" {
		envUpdates["RESTIC_PASSWORD_FILE"] = passwordFilePath
	}
	if c.repository != nil && c.repository.URL != "" {
		envUpdates["RESTIC_REPOSITORY"] = c.repository.URL
	}

	for _, envPath := range dedupeEnvPaths(envPaths) {
		if !filepath.IsAbs(envPath) {
			logger.Debug("Skipping .env update (path not absolute)",
				zap.String("path", envPath))
			continue
		}

		if err := upsertEnvFile(envPath, envUpdates); err != nil {
			logger.Warn("Failed to update .env file",
				zap.String("path", envPath),
				zap.Error(err))
			continue
		}

		envWritten = true
		logger.Info("terminal prompt:", zap.String("output",
			fmt.Sprintf("✓ Updated %s with restic credentials", envPath)))
	}

	if !fileWritten && !envWritten {
		return fmt.Errorf("unable to persist restic password to disk")
	}

	return nil
}

func writePasswordFile(path, password string) error {
	if path == "" {
		return fmt.Errorf("password file path is empty")
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	if _, err := os.Stat(path); err == nil {
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("preparing password file %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("checking password file %s: %w", path, err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("opening password file %s: %w", path, err)
	}

	if _, err := file.WriteString(password + "\n"); err != nil {
		file.Close()
		return fmt.Errorf("writing password file %s: %w", path, err)
	}

	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("syncing password file %s: %w", path, err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("closing password file %s: %w", path, err)
	}

	if err := os.Chmod(path, PasswordFilePerm); err != nil {
		return fmt.Errorf("setting permissions on %s: %w", path, err)
	}

	return nil
}

func upsertEnvFile(path string, updates map[string]string) error {
	createdNew := false
	lines := []string{}

	data, err := os.ReadFile(path)
	if err == nil {
		raw := strings.ReplaceAll(string(data), "\r\n", "\n")
		lines = strings.Split(raw, "\n")
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
	} else {
		if !os.IsNotExist(err) {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		createdNew = true
	}

	applied := make(map[string]bool, len(updates))
	for key := range updates {
		applied[key] = false
	}

	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		if value, ok := updates[key]; ok {
			lines[idx] = fmt.Sprintf("%s=%s", key, quoteEnvValue(value))
			applied[key] = true
		}
	}

	for key, done := range applied {
		if done {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s=%s", key, quoteEnvValue(updates[key])))
	}

	if createdNew {
		header := "# Generated by eos backup wizard"
		lines = append([]string{header, ""}, lines...)
	}

	content := strings.Join(lines, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating directory for %s: %w", path, err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(content), 0o600); err != nil {
		return fmt.Errorf("writing temp env file %s: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("setting permissions on %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replacing env file %s: %w", path, err)
	}

	return nil
}

func quoteEnvValue(value string) string {
	if value == "" {
		return ""
	}

	if strings.ContainsAny(value, " #\"'\t\r\n") {
		return strconv.Quote(value)
	}

	return value
}

func dedupeEnvPaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	result := make([]string, 0, len(paths))

	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		result = append(result, path)
	}

	return result
}
