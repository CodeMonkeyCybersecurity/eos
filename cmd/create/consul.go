// cmd/create/consul.go

package create

import (
	"fmt"
	"os"
	"os/exec"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateConsulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Install and configure Consul on the local machine",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger, _ := zap.NewProduction()
		sugar := logger.Sugar()
		sugar.Info("Starting Consul setup...")

		// Check if Consul is already installed
		if _, err := exec.LookPath("consul"); err != nil {
			sugar.Info("Consul not found, installing...")

			downloadCmd := exec.Command("bash", "-c", `curl -fsSL https://releases.hashicorp.com/consul/1.17.1/consul_1.17.1_linux_amd64.zip -o consul.zip`)
			downloadCmd.Stdout = os.Stdout
			downloadCmd.Stderr = os.Stderr
			if err := downloadCmd.Run(); err != nil {
				return fmt.Errorf("failed to download Consul: %w", err)
			}

			unzipCmd := exec.Command("unzip", "-o", "consul.zip")
			unzipCmd.Stdout = os.Stdout
			unzipCmd.Stderr = os.Stderr
			if err := unzipCmd.Run(); err != nil {
				return fmt.Errorf("failed to unzip Consul: %w", err)
			}

			moveCmd := exec.Command("sudo", "mv", "consul", "/usr/local/bin/")
			moveCmd.Stdout = os.Stdout
			moveCmd.Stderr = os.Stderr
			if err := moveCmd.Run(); err != nil {
				return fmt.Errorf("failed to move Consul binary: %w", err)
			}
		}

		// Use Consul API to verify interaction and prepare config dir
		sugar.Info("Creating minimal Consul config using SDK...")
		config := consulapi.DefaultConfig()
		client, err := consulapi.NewClient(config)
		if err != nil {
			return fmt.Errorf("failed to create Consul client: %w", err)
		}

		// Create a dummy KV key to verify it's working
		kv := client.KV()
		pair := &consulapi.KVPair{Key: "eos/consul/test", Value: []byte("initialized")}
		_, err = kv.Put(pair, nil)
		if err != nil {
			return fmt.Errorf("failed to write KV to Consul: %w", err)
		}

		sugar.Info("KV test key written successfully. Starting local agent in dev mode...")

		// Start Consul dev agent
		script := `
			set -e
			sudo useradd --system --home /etc/consul.d --shell /bin/false consul || true
			sudo mkdir -p /etc/consul.d /opt/consul
			sudo chown -R consul:consul /etc/consul.d /opt/consul
			sudo chmod 750 /etc/consul.d
			cat <<EOF | sudo tee /etc/systemd/system/consul.service
[Unit]
Description=Consul Agent
Requires=network-online.target
After=network-online.target

[Service]
User=consul
Group=consul
ExecStart=/usr/local/bin/consul agent -dev -node=consul-dev -bind=127.0.0.1 -client=0.0.0.0 -data-dir=/opt/consul -config-dir=/etc/consul.d
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
			sudo systemctl daemon-reload
			sudo systemctl enable consul
			sudo systemctl start consul
		`

		setupCmd := exec.Command("bash", "-c", script)
		setupCmd.Stdout = os.Stdout
		setupCmd.Stderr = os.Stderr
		if err := setupCmd.Run(); err != nil {
			return fmt.Errorf("failed to configure and start Consul: %w", err)
		}

		sugar.Info("Consul installation and startup complete.")
		return nil
	},
}
