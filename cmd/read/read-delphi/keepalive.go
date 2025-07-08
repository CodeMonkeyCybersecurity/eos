// cmd/delphi/read/keepalive.go

package read

import (
	"encoding/json"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var ReadKeepAliveCmd = &cobra.Command{
	Use:   "keepalive",
	Short: "Check disconnected agents from Wazuh API",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		cfg, err := delphi.ResolveConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to resolve Delphi config", zap.Error(err))
		}
		if cfg.Protocol == "" {
			cfg.Protocol = "https"
		}
		if cfg.Port == "" {
			cfg.Port = "55000"
		}
		if cfg.Endpoint == "" {
			cfg.Endpoint = "/agents?select=lastKeepAlive&select=id&status=disconnected"
		}
		baseURL := fmt.Sprintf("%s://%s:%s%s", cfg.Protocol, cfg.FQDN, cfg.Port, cfg.Endpoint)

		otelzap.Ctx(rc.Ctx).Info("Sending GET request to Wazuh", zap.String("url", baseURL))

		headers := map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", cfg.Token),
			"Content-Type":  "application/json",
		}

		response, err := delphi.GetJSON(rc, baseURL, headers)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to fetch keepalive data", zap.Error(err))
		}

		pretty, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to format JSON", zap.Error(err))
		}
		fmt.Println("Disconnected agents:")
		fmt.Println(string(pretty))
		return nil
	}),
}

func init() {
	ReadCmd.AddCommand(ReadKeepAliveCmd)
}
