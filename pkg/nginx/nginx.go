package nginx

import (
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
)

//
//---------------------------- NGINX FUNCTIONS ---------------------------- //
//

// DeployApp deploys an application by copying necessary configs and restarting services
func DeployApp(rc *eos_io.RuntimeContext, app string, cmd *cobra.Command) error {
	otelzap.Ctx(rc.Ctx).Info("Starting deployment", zap.String("app", app))
	fmt.Printf("Deploying %s...\n", app)

	// helper to copy *.conf
	copyConf := func(srcDir, outDir string) error {
		src := filepath.Join(srcDir, app+".conf")
		dst := filepath.Join(outDir, app+".conf")
		return eos_unix.CopyFile(rc.Ctx, src, dst, 0o644)
	}

	// HTTP config
	if err := copyConf(filepath.Join(AssetsPath, "servers"), NginxConfPath); err != nil {
		if !eos_unix.Exists(filepath.Join(AssetsPath, "servers", app+".conf")) {
			otelzap.Ctx(rc.Ctx).Error("Missing HTTP config", zap.String("file", filepath.Join(AssetsPath, "servers", app+".conf")))
			return fmt.Errorf("missing Nginx HTTP config for %s", app)
		}
		return fmt.Errorf("copy HTTP config: %w", err)
	}

	// Stream config (optional)
	if eos_unix.Exists(filepath.Join(AssetsPath, "stream", app+".conf")) {
		if err := copyConf(filepath.Join(AssetsPath, "stream"), NginxStreamPath); err != nil {
			return fmt.Errorf("copy Stream config: %w", err)
		}
	}

	// Nextcloud “talk” service
	if app == "nextcloud" {
		noTalk, _ := cmd.Flags().GetBool("without-talk")
		if !noTalk {
			otelzap.Ctx(rc.Ctx).Info("Deploying Coturn for NextCloud Talk")
			if err := container.RunDockerComposeAllServices(DefaultComposeYML, "coturn"); err != nil {
				return fmt.Errorf("failed to deploy Coturn: %w", err)
			}
		} else {
			otelzap.Ctx(rc.Ctx).Info("Skipping Coturn deployment")
		}
	}

	// Validate & restart
	if err := ValidateNginx(rc); err != nil {
		return fmt.Errorf("invalid Nginx configuration: %w", err)
	}
	if err := RestartNginx(rc); err != nil {
		return fmt.Errorf("failed to restart Nginx: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info("Deployment successful", zap.String("app", app))
	fmt.Printf("Successfully deployed %s!\n", app)
	return nil
}

// ValidateNginx runs `nginx -t` to check configuration validity
func ValidateNginx(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info("Validating Nginx configuration...")
	cmd := exec.Command("nginx", "-t")
	output, err := cmd.CombinedOutput() // Capture full output
	fmt.Println(string(output))         // Print to console for visibility

	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Nginx configuration validation failed",
			zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("nginx validation failed: %s", output)
	}
	otelzap.Ctx(rc.Ctx).Info("Nginx configuration is valid", zap.String("output", "\n"+string(output)))
	return nil
}

// RestartNginx reloads the Nginx service
func RestartNginx(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info("Restarting Nginx...")
	cmd := exec.Command("systemctl", "reload", "nginx")
	output, err := cmd.CombinedOutput() // Capture full output
	fmt.Println(string(output))         // Print to console

	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to restart Nginx",
			zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("nginx reload failed: %s", output)
	}
	otelzap.Ctx(rc.Ctx).Info("Nginx restarted successfully", zap.String("output", "\n"+string(output)))
	return nil
}
