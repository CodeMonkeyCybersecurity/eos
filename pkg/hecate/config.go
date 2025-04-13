// pkg/hecate/config.go

package hecate

import (
	"bufio"

	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/types"
)

//
// ---------------------------- HECATE CONFIGURATION ---------------------------- //

type HecateConfig struct {
	BaseDomain string
	BackendIP  string
	Subdomain  string
	Email      string
}

func LoadConfig(defaultSubdomain string) (*HecateConfig, error) {
	cfg := &HecateConfig{}

	if _, err := os.Stat(types.HecateLastValuesFile); err == nil {
		f, err := os.Open(types.HecateLastValuesFile)
		if err != nil {

			return nil, fmt.Errorf("unable to open %s: %w", types.HecateLastValuesFile, err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
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

			return nil, fmt.Errorf("error reading %s: %w", types.HecateLastValuesFile, err)
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
	if err := os.WriteFile(types.HecateLastValuesFile, []byte(content), 0644); err != nil {

		return nil, fmt.Errorf("failed to write %s: %w", types.HecateLastValuesFile, err)
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
