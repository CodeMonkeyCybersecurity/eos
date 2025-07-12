// cmd/read/authentik.go

package read

import (
	"fmt"
	"io"
	"net/http"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/exportutil"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	akBaseURL, akToken, akOut string
)

var AuthentikCmd = &cobra.Command{
	Use:   "authentik",
	Short: "Export Authentik blueprints to YAML",
	Long: `Export Authentik configuration blueprints to YAML format.

This command connects to an Authentik instance and exports all configured
blueprints, including flows, policies, property mappings, and providers.

Features:
  - Exports complete Authentik configuration
  - Saves to timestamped YAML file
  - Supports custom output paths
  - Secure token handling

Examples:
  # Export with environment variables
  export AK_URL=https://id.example.com
  export AK_TOKEN=your-api-token
  eos read authentik
  
  # Export with command line flags
  eos read authentik --ak-url https://id.dev.local --ak-token $TOKEN
  
  # Export to custom path
  eos read authentik --out /path/to/blueprints.yaml`,
	Example: `eos inspect authentik \
  --ak-url https://id.dev.local \
  AK_TOKEN=$(cat /run/secrets/ak_pat) eos …`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, _ *cobra.Command, _ []string) error {
		l := otelzap.Ctx(rc.Ctx)
		if akBaseURL == "" || akToken == "" {
			return fmt.Errorf("ak-url and ak-token are required (can come from env)")
		}
		url := fmt.Sprintf("%s/api/v3/blueprints/export/", akBaseURL)

		req, _ := http.NewRequestWithContext(rc.Ctx, http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+akToken)
		req.Header.Set("Accept", "text/yaml")
		l.Info("Authentik export", zap.String("url", url), zap.String("token", akToken[:6]+"…"))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				l.Warn("Failed to close response body", zap.Error(err))
			}
		}()
		if resp.StatusCode != http.StatusOK {
			buf, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return fmt.Errorf("authentik export failed: %s – %s", resp.Status, string(buf))
		}

		if akOut == "" {
			if err := exportutil.EnsureDir(); err != nil {
				return err
			}
			akOut, err = exportutil.Build("authentik", "yaml")
			if err != nil {
				return err
			}
		}
		fd, err := os.OpenFile(akOut, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer func() {
			if err := fd.Close(); err != nil {
				l.Warn("Failed to close file", zap.String("file", akOut), zap.Error(err))
			}
		}()
		n, err := io.Copy(fd, resp.Body)
		if err != nil {
			return err
		}
		l.Info("Blueprints exported",
			zap.String("file", akOut),
			zap.Int64("bytes", n),
		)
		return nil
	}),
}

func init() {
	AuthentikCmd.Flags().StringVar(&akBaseURL, "ak-url", os.Getenv("AK_URL"), "Base URL (required)")
	AuthentikCmd.Flags().StringVar(&akToken, "ak-token", os.Getenv("AK_TOKEN"), "API token (required)")
	AuthentikCmd.Flags().StringVar(&akOut, "out", "", "Override output path")
}
