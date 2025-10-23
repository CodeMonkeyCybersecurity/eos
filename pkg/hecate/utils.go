// pkg/hecate/util_render.go

package hecate

import (
	"bytes"
	"fmt"
	"os"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func appendToFile(path string, content string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			// Log silently for file operations
			_ = err
		}
	}()

	if _, err := f.WriteString(content + "\n"); err != nil {
		return err
	}
	return nil
}

func renderTemplateFromString(tmplStr string, data interface{}) (string, error) {
	tmpl, err := template.New("compose").Parse(tmplStr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// RenderBundleFragments renders and writes Compose, Caddy, and Nginx fragments as needed.
func RenderBundleFragments(
	rc *eos_io.RuntimeContext,
	bundle ServiceBundle,
	composeOverridePath string,
	caddyTargetDir string,
	nginxTargetDir string,
	serviceKey string,
) error {
	log := otelzap.Ctx(rc.Ctx)

	// === Compose ===
	if bundle.Compose != nil {
		for name, svc := range bundle.Compose.Services {
			log.Info(" Rendering Compose service", zap.String("service", name))

			rendered, err := renderTemplateFromString(svc.FullServiceYAML, svc.Environment)
			if err != nil {
				log.Error("Failed to render Compose", zap.String("service", name), zap.Error(err))
				return fmt.Errorf("failed to render Compose %s: %w", name, err)
			}

			err = appendToFile(composeOverridePath, rendered)
			if err != nil {
				log.Error("Failed to write Compose", zap.String("service", name), zap.Error(err))
				return fmt.Errorf("failed to write Compose %s: %w", name, err)
			}
			log.Info(" Compose block written", zap.String("service", name))
		}
	}

	// === Caddy ===
	if bundle.Caddy != nil {
		content, err := RenderCaddyfileContent(*bundle.Caddy)
		if err != nil {
			log.Error("Failed to render Caddyfile", zap.Error(err))
			return fmt.Errorf("failed to render Caddyfile: %w", err)
		}

		if err := os.MkdirAll(caddyTargetDir, 0755); err != nil {
			log.Error("Failed to create Caddy dir", zap.Error(err))
			return fmt.Errorf("failed to create Caddy dir: %w", err)
		}

		filePath := fmt.Sprintf("%s/%s.caddy", caddyTargetDir, serviceKey)
		err = os.WriteFile(filePath, []byte(content), 0644)
		if err != nil {
			log.Error("Failed to write Caddy", zap.Error(err))
			return fmt.Errorf("failed to write Caddy: %w", err)
		}
		log.Info(" Caddy block written", zap.String("path", filePath))
	}

	// === Nginx ===
	if bundle.Nginx != nil {
		rendered, err := RenderStreamBlocks(shared.GetInternalHostname(), bundle.Nginx.StreamBlocks)
		if err != nil {
			log.Error("Failed to render Nginx stream blocks", zap.Error(err))
			return fmt.Errorf("failed to render Nginx stream blocks: %w", err)
		}

		if err := os.MkdirAll(nginxTargetDir, 0755); err != nil {
			log.Error("Failed to create Nginx dir", zap.Error(err))
			return fmt.Errorf("failed to create Nginx dir: %w", err)
		}

		filePath := fmt.Sprintf("%s/%s.conf", nginxTargetDir, serviceKey)
		err = os.WriteFile(filePath, []byte(rendered), 0644)
		if err != nil {
			log.Error("Failed to write Nginx block", zap.Error(err))
			return fmt.Errorf("failed to write Nginx: %w", err)
		}
		log.Info(" Nginx block written", zap.String("path", filePath))
	}

	return nil
}

// GenericWizard handles user prompts and builds a ServiceBundle.
func GenericWizard(
	rc *eos_io.RuntimeContext,
	logName string,
	prompts []PromptField,
	serviceName string,
	serviceYAML string,
	caddyProxy *CaddyAppProxy, // nil if no Caddy needed
	nginxSpec *NginxSpec, // nil if no Nginx needed
	dependsOn []string,
	volumes []string,
	ports []string,
) ServiceBundle {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Collecting setup information...")

	env := make(map[string]string)
	for _, field := range prompts {
		val := interaction.PromptInputWithReader(rc.Ctx, field.Prompt, field.Default, field.Reader)
		env[field.EnvVar] = val
	}

	// === Compose Spec ===
	svcSpec := &ServiceSpec{
		Name:            serviceName,
		FullServiceYAML: serviceYAML,
		Environment:     env,
		DependsOn:       dependsOn,
		Volumes:         volumes,
		Ports:           ports,
	}
	composeSpec := &ComposeSpec{
		Services: map[string]*ServiceSpec{
			serviceName: svcSpec,
		},
	}

	var caddySpec *CaddySpec
	if caddyProxy != nil {
		caddySpec = &CaddySpec{
			Proxies: []CaddyAppProxy{*caddyProxy},
		}
	}

	log.Info(" ServiceBundle prepared", zap.String("service", serviceName))

	return ServiceBundle{
		Compose: composeSpec,
		Caddy:   caddySpec,
		Nginx:   nginxSpec,
	}
}

func RenderAndWriteTemplate(
	rc *eos_io.RuntimeContext,
	logName string,
	templateContent string,
	data any,
	outputPath string,
) error {
	log := otelzap.Ctx(rc.Ctx)

	tmpl, err := template.New("template").Parse(templateContent)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		log.Error("Failed to write rendered file", zap.Error(err), zap.String("path", outputPath))
		return fmt.Errorf("failed to write file: %w", err)
	}

	log.Info(" Template written successfully", zap.String("path", outputPath))
	return nil
}
