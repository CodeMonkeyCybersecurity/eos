// pkg/hecate/config.go

package hecate

import (
	"bufio"

	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

//
// ---------------------------- HECATE CONFIGURATION ---------------------------- //

type HecateBasicConfig struct {
	BaseDomain string
	BackendIP  string
	Subdomain  string
	Email      string
}

func LoadConfig(rc *eos_io.RuntimeContext, defaultSubdomain string) (*HecateBasicConfig, error) {
	cfg := &HecateBasicConfig{}

	if _, err := os.Stat(shared.HecateLastValuesFile); err == nil {
		file, err := os.Open(shared.HecateLastValuesFile)
		if err != nil {

			return nil, fmt.Errorf("unable to open %s: %w", shared.HecateLastValuesFile, err)
		}
		defer func() {
			if err := file.Close(); err != nil {
				otelzap.Ctx(rc.Ctx).Warn("Failed to close log file", zap.Error(err))
			}
		}()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "BASE_DOMAIN="):
				cfg.BaseDomain = strings.TrimSpace(strings.TrimPrefix(line, "BASE_DOMAIN="))

			case strings.HasPrefix(line, "backendIP="):
				cfg.BackendIP = strings.TrimSpace(strings.TrimPrefix(line, "backendIP="))

			case strings.HasPrefix(line, "SUBDOMAIN="):
				cfg.Subdomain = strings.TrimSpace(strings.TrimPrefix(line, "SUBDOMAIN="))

			case strings.HasPrefix(line, "EMAIL="):
				cfg.Email = strings.TrimSpace(strings.TrimPrefix(line, "EMAIL="))

			}
		}
		if err := scanner.Err(); err != nil {

			return nil, fmt.Errorf("error reading %s: %w", shared.HecateLastValuesFile, err)
		}
	}

	// Handle missing configuration values and log the prompts
	if cfg.Subdomain == "" && defaultSubdomain != "" {
		cfg.Subdomain = defaultSubdomain

	}

	// Check if there are missing fields and log them
	missing := []string{}
	if cfg.BaseDomain == "" {
		missing = append(missing, "Base Domain")
	}
	if cfg.BackendIP == "" {
		missing = append(missing, "Backend IP")
	}
	if cfg.Email == "" {
		missing = append(missing, "Email")
	}
	if len(missing) > 0 {

		fmt.Printf("The following fields need to be set: %s\n", strings.Join(missing, ", "))
		if cfg.BaseDomain == "" {
			cfg.BaseDomain = prompt("Please enter the Base Domain (e.g., example.com): ")
		}
		if cfg.BackendIP == "" {
			cfg.BackendIP = prompt("Please enter the Backend IP (e.g., 192.168.1.100): ")
		}
		if cfg.Email == "" {
			cfg.Email = prompt("Please enter the email address for certificate requests (e.g., admin@example.com): ")
		}
	}

	// Log when configuration is written
	content := fmt.Sprintf("BASE_DOMAIN=%s\nbackendIP=%s\nSUBDOMAIN=%s\nEMAIL=%s\n",
		cfg.BaseDomain, cfg.BackendIP, cfg.Subdomain, cfg.Email)
	if err := os.WriteFile(shared.HecateLastValuesFile, []byte(content), shared.ConfigFilePerm); err != nil {

		return nil, fmt.Errorf("failed to write %s: %w", shared.HecateLastValuesFile, err)
	}

	return cfg, nil
}

func prompt(message string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(message)
	text, _ := reader.ReadString('\n')
	userInput := strings.TrimSpace(text)

	// Log the user input action, but avoid logging sensitive information.

	return userInput
}
