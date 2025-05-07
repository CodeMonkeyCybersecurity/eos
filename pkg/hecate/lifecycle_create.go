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
	serviceChoices := []struct {
		name              string
		prompt            string
		defaultYes        bool
		setupFunc         func(*bufio.Reader) ServiceBundle
		useTemplateRender bool
	}{
		{"Keycloak", "Do you want to set up Keycloak?", false, SetupKeycloakWizard, false},
		{"Nextcloud", "Do you want to set up Nextcloud?", false, SetupNextcloudWizard, true},
		{"Wazuh", "Do you want to set up Wazuh?", false, SetupWazuhWizard, false},
		{"Jenkins", "Do you want to set up Jenkins?", false, SetupJenkinsWizard, false},
	}

	// Prompt the user for each service
	enabledServices := []struct {
		name              string
		bundle            ServiceBundle
		useTemplateRender bool
	}{}

	for _, svc := range serviceChoices {
		if interaction.PromptYesNo(svc.prompt, svc.defaultYes) {
			bundle := svc.setupFunc(reader)
			enabledServices = append(enabledServices, struct {
				name              string
				bundle            ServiceBundle
				useTemplateRender bool
			}{svc.name, bundle, svc.useTemplateRender})
		}
	}

	// Check: Exit early if no services selected
	if len(enabledServices) == 0 {
		zap.L().Named("hecate-setup-check").Warn("🚫 No services selected. Exiting without making any changes.")
		return errors.New("no services selected; exiting setup wizard")
	}

	// Ask for the backend IP once
	backendIP := interaction.PromptInputWithReader("Enter the backend IP address for these services:", "", reader)

	// Process each enabled service
	for _, svc := range enabledServices {
		if err := handleService(log, svc.name, svc.bundle, backendIP, svc.useTemplateRender); err != nil {
			return fmt.Errorf("failed to process %s: %w", svc.name, err)
		}
	}

	// === Collate everything at the end ===

	// Caddyfile
	if err := CollateAndWriteFile(
		"hecate-caddy-collation",
		caddyFragments,
		HecateCaddyfile,
		"",
		"",
		func(frag CaddyFragment) string { return frag.CaddyBlock },
	); err != nil {
		return err
	}

	// docker-compose.yml
	if err := CollateAndWriteFile(
		"hecate-compose-collation",
		composeFragments,
		HecateDockerCompose,
		"services:\n",
		DockerNetworkAndVolumes,
		func(frag DockerComposeFragment) string { return frag.ServiceYAML },
	); err != nil {
		return err
	}

	// nginx.conf (only if fragments exist)
	if len(nginxFragments) > 0 {
		if err := CollateAndWriteFile(
			"hecate-nginx-collation",
			nginxFragments,
			HecateNginxConfig,
			BaseNginxConf,
			"",
			func(_ NginxFragment) string { return "" },
		); err != nil {
			return err
		}
	} else {
		zap.L().Named("hecate-nginx-collation").Info("No Nginx fragments to write; skipping nginx.conf")
	}

	return nil
}

// handleService processes the ServiceBundle and appends fragments.
func handleService(
	log *zap.Logger,
	name string,
	bundle ServiceBundle,
	backendIP string,
	useTemplateRender bool,
) error {

	if bundle.Caddy != nil {
		frag, err := bundle.Caddy.ToFragment(backendIP)
		if err != nil {
			return fmt.Errorf("failed to render Caddy fragment for %s: %w", name, err)
		}
		caddyFragments = append(caddyFragments, frag)
	}

	if bundle.Nginx != nil {
		frag, err := bundle.Nginx.ToFragment(backendIP)
		if err != nil {
			return fmt.Errorf("failed to render Nginx fragment for %s: %w", name, err)
		}
		nginxFragments = append(nginxFragments, frag)
	}

	if bundle.Compose != nil && bundle.Compose.Services != nil {
		for svcName, svc := range bundle.Compose.Services {
			if useTemplateRender {
				rendered, err := renderTemplateFromString(svc.FullServiceYAML, svc.Environment)
				if err != nil {
					log.Warn("Failed to render service YAML", zap.String("service", svcName), zap.Error(err))
					continue
				}
				frag := DockerComposeFragment{ServiceYAML: rendered}
				composeFragments = append(composeFragments, frag)
			} else {
				frag, err := svc.ToFragment()
				if err != nil {
					log.Warn("Failed to render service fragment", zap.String("service", svcName), zap.Error(err))
					continue
				}
				composeFragments = append(composeFragments, frag)
			}
		}
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

func CollateAndWriteFile[T any](
	logName string,
	fragments []T,
	filePath string,
	header string,
	footer string,
	renderFunc func(T) string,
) error {
	log := zap.L().Named(logName)

	// Skip file creation if no fragments & no header/footer
	if len(fragments) == 0 && header == "" && footer == "" {
		log.Info("No fragments to write; skipping", zap.String("path", filePath))
		return nil
	}

	var buf bytes.Buffer

	if header != "" {
		buf.WriteString(header)
		if header[len(header)-1] != '\n' {
			buf.WriteString("\n")
		}
	}

	for _, frag := range fragments {
		buf.WriteString(renderFunc(frag))
		buf.WriteString("\n\n")
	}

	if footer != "" {
		buf.WriteString(footer)
	}

	err := os.WriteFile(filePath, buf.Bytes(), 0644)
	if err != nil {
		log.Error("Failed to write file", zap.Error(err), zap.String("path", filePath))
		return fmt.Errorf("failed to write file %s: %w", filePath, err)
	}

	log.Info("✅ Final file written successfully", zap.String("path", filePath))
	return nil
}
