// pkg/hecate/lifecycle_create.go

package hecate

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"go.uber.org/zap"
)

func SetupHecateWizard() error {
	log := zap.L().Named("hecate-setup-wizard")
	reader := bufio.NewReader(os.Stdin)

	log.Info("🚀 Welcome to the Hecate setup wizard!")

	if err := system.EnsureDir(BaseDir); err != nil {
		log.Error("Failed to create /opt/hecate directory", zap.Error(err))
		return fmt.Errorf("failed to create /opt/hecate directory: %w", err)
	}

	// === Service selection ===
	keycloakEnabled := interaction.PromptYesNo("Do you want to set up Keycloak?", true)
	nextcloudEnabled := interaction.PromptYesNo("Do you want to set up Nextcloud (Coturn only)?", false)
	wazuhEnabled := interaction.PromptYesNo("Do you want to set up Wazuh?", false)
	jenkinsEnabled := interaction.PromptYesNo("Do you want to set up Jenkins?", false)

	// Check: Exit early if no services selected
	if ShouldExitNoServicesSelected(keycloakEnabled, nextcloudEnabled, wazuhEnabled, jenkinsEnabled) {
		return errors.New("no services selected; exiting setup wizard")
	}

	// Ask for the backend IP once (or you can customize per service if needed)
	var backendIP = interaction.PromptInputWithReader("Enter the backend IP address for these services:", "", reader)

	// === Process each service ===
	if keycloakEnabled {
		bundle := SetupKeycloakWizard(reader)

		if bundle.Caddy != nil {
			frag, err := bundle.Caddy.ToFragment(backendIP)
			if err != nil {
				return fmt.Errorf("failed to render Caddy fragment for Keycloak: %w", err)
			}
			caddyFragments = append(caddyFragments, frag)
		}
		if bundle.Nginx != nil {
			frag, err := bundle.Nginx.ToFragment(backendIP)
			if err != nil {
				return fmt.Errorf("failed to render Nginx fragment for Keycloak: %w", err)
			}
			nginxFragments = append(nginxFragments, frag)
		}
		if bundle.Compose != nil && bundle.Compose.Services != nil {
			for name, svc := range bundle.Compose.Services {
				frag, err := svc.ToFragment()
				if err != nil {
					log.Warn("Failed to render service fragment", zap.String("service", name), zap.Error(err))
					continue
				}
				composeFragments = append(composeFragments, frag)
			}
		}
	}

	if wazuhEnabled {
		bundle := SetupWazuhWizard(reader)

		if bundle.Caddy != nil {
			frag, err := bundle.Caddy.ToFragment(backendIP)
			if err != nil {
				return fmt.Errorf("failed to render Caddy fragment for Wazuh: %w", err)
			}
			caddyFragments = append(caddyFragments, frag)
		}
		if bundle.Nginx != nil {
			frag, err := bundle.Nginx.ToFragment(backendIP)
			if err != nil {
				return fmt.Errorf("failed to render Nginx fragment for Wazuh: %w", err)
			}
			nginxFragments = append(nginxFragments, frag)
		}
		if bundle.Compose != nil && bundle.Compose.Services != nil {
			for name, svc := range bundle.Compose.Services {
				frag, err := svc.ToFragment()
				if err != nil {
					log.Warn("Failed to render service fragment", zap.String("service", name), zap.Error(err))
					continue
				}
				composeFragments = append(composeFragments, frag)
			}
		}
	}

	if jenkinsEnabled {
		bundle := SetupJenkinsWizard(reader)

		if bundle.Caddy != nil {
			frag, err := bundle.Caddy.ToFragment(backendIP)
			if err != nil {
				return fmt.Errorf("failed to render Caddy fragment for Jenkins: %w", err)
			}
			caddyFragments = append(caddyFragments, frag)
		}
		if bundle.Nginx != nil {
			frag, err := bundle.Nginx.ToFragment(backendIP)
			if err != nil {
				return fmt.Errorf("failed to render Nginx fragment for Jenkins: %w", err)
			}
			nginxFragments = append(nginxFragments, frag)
		}
		if bundle.Compose != nil && bundle.Compose.Services != nil {
			for name, svc := range bundle.Compose.Services {
				frag, err := svc.ToFragment()
				if err != nil {
					log.Warn("Failed to render service fragment", zap.String("service", name), zap.Error(err))
					continue
				}
				composeFragments = append(composeFragments, frag)
			}
		}
	}

	if nextcloudEnabled {
		bundle := SetupNextcloudWizard(reader)

		if bundle.Caddy != nil {
			frag, err := bundle.Caddy.ToFragment(backendIP)
			if err != nil {
				return fmt.Errorf("failed to render Caddy fragment for Nextcloud: %w", err)
			}
			caddyFragments = append(caddyFragments, frag)
		}
		if bundle.Nginx != nil {
			frag, err := bundle.Nginx.ToFragment(backendIP)
			if err != nil {
				return fmt.Errorf("failed to render Nginx fragment for Nextcloud: %w", err)
			}
			nginxFragments = append(nginxFragments, frag)
		}
		if bundle.Compose != nil && bundle.Compose.Services != nil {
			for name, svc := range bundle.Compose.Services {
				frag, err := svc.ToFragment()
				if err != nil {
					log.Warn("Failed to render service fragment", zap.String("service", name), zap.Error(err))
					continue
				}
				composeFragments = append(composeFragments, frag)
			}
		}
	}

	// === Collate everything at the end ===
	if err := CollateAndWriteCaddyfile(caddyFragments); err != nil {
		return err
	}
	if err := CollateAndWriteDockerCompose(composeFragments); err != nil {
		return err
	}
	if err := CollateAndWriteNginxConfig(nginxFragments); err != nil {
		return err
	}

	return nil
}

// ShouldExitNoServicesSelected checks if no services were selected and logs a friendly exit message.
func ShouldExitNoServicesSelected(keycloak, nextcloud, wazuh, jenkins bool) bool {
	if !keycloak && !nextcloud && !wazuh && !jenkins {
		zap.L().Named("hecate-setup-check").Warn("🚫 No services selected. Exiting without making any changes.")
		return true
	}
	return false
}

// CollateAndWriteDockerCompose merges multiple DockerComposeFragment pieces and writes the docker-compose.yml.
func CollateAndWriteDockerCompose(fragments []DockerComposeFragment) error {
	log := zap.L().Named("hecate-compose-collation")

	var buf bytes.Buffer

	// Header (optional, can add version info here)
	buf.WriteString("version: '3.8'\n\nservices:\n")

	for _, frag := range fragments {
		buf.WriteString(frag.ServiceYAML)
		buf.WriteString("\n\n")
	}

	// Add networks & volumes at the end
	buf.WriteString(DockerNetworkAndVolumes)

	composeFilePath := HecateDockerCompose
	err := os.WriteFile(composeFilePath, buf.Bytes(), 0644)
	if err != nil {
		log.Error("Failed to write docker-compose.yml", zap.Error(err),
			zap.String("path", composeFilePath),
		)
		return fmt.Errorf("failed to write docker-compose.yml: %w", err)
	}

	log.Info("✅ Final docker-compose.yml written successfully", zap.String("path", composeFilePath))
	return nil
}

// CollateAndWriteCaddyfile merges multiple CaddyConfig fragments and writes the final Caddyfile.
func CollateAndWriteCaddyfile(fragments []CaddyFragment) error {
	log := zap.L().Named("hecate-caddy-collation")

	var buf bytes.Buffer
	for _, frag := range fragments {
		buf.WriteString(frag.CaddyBlock)
		buf.WriteString("\n\n")
	}

	caddyfilePath := HecateCaddyfile
	err := os.WriteFile(caddyfilePath, buf.Bytes(), 0644)
	if err != nil {
		log.Error("Failed to write Caddyfile", zap.Error(err),
			zap.String("path", caddyfilePath),
		)
		return fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	log.Info("✅ Final Caddyfile written successfully", zap.String("path", caddyfilePath))
	return nil
}

// CollateAndWriteNginxConfig writes the main nginx.conf that includes service fragments.
func CollateAndWriteNginxConfig(_ []NginxFragment) error {
	log := zap.L().Named("hecate-nginx-collation")

	// Minimal nginx.conf that includes the stream fragments
	mainConf := `
worker_processes  1;

events {
    worker_connections  1024;
}

` + StreamIncludeTemplate + `
`

	nginxFilePath := HecateNginxConfig
	err := os.WriteFile(nginxFilePath, []byte(mainConf), 0644)
	if err != nil {
		log.Error("Failed to write nginx.conf", zap.Error(err),
			zap.String("path", nginxFilePath),
		)
		return fmt.Errorf("failed to write nginx.conf: %w", err)
	}

	log.Info("✅ Main nginx.conf written successfully, using stream includes",
		zap.String("path", nginxFilePath),
	)
	return nil
}
