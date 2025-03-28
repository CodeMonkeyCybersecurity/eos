// cmd/delphi/inspect/keepalive.go

package inspect

import (
	"encoding/json"
	"eos/pkg/delphi"
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var KeepAliveCmd = &cobra.Command{
	Use:   "keepalive",
	Short: "Check disconnected agents from Wazuh API",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := delphi.LoadConfig()
		if err != nil {
			log.Fatal("Failed to load Delphi config", zap.Error(err))
		}

		cfg = delphi.ConfirmConfig(cfg)
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

		log.Info("Sending GET request to Wazuh", zap.String("url", baseURL))

		headers := map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", cfg.Token),
			"Content-Type":  "application/json",
		}

		response, err := delphi.GetJSON(baseURL, headers)
		if err != nil {
			log.Fatal("Failed to fetch keepalive data", zap.Error(err))
		}

		pretty, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			log.Fatal("Failed to format JSON", zap.Error(err))
		}
		fmt.Println("Disconnected agents:")
		fmt.Println(string(pretty))
	},
}
