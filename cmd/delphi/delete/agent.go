// cmd/delphi/delete/agent.go
package delete

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var agentID string

var DeleteAgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Delete a Wazuh agent using its agent ID",
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()

		if agentID == "" {
			log.Error("Agent ID is required")
			fmt.Println("❌ Please provide an agent ID using --agent-id")
			return
		}

		log.Info("Loading and confirming Delphi API configuration...")
		config, err := delphi.LoadAndConfirmConfig()
		if err != nil {
			log.Error("Failed to load config", zap.Error(err))
			os.Exit(1)
		}

		token, err := delphi.Authenticate(config)
		if err != nil {
			log.Error("Authentication failed", zap.Error(err))
			os.Exit(1)
		}

		log.Info("Attempting to delete Wazuh agent", zap.String("agentID", agentID))
		resp, err := delphi.DeleteAgent(agentID, token, config)
		if err != nil {
			log.Error("Failed to delete agent", zap.Error(err))
			os.Exit(1)
		}

		prettyJSON, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println("\n✅ Agent deleted successfully. Response:\n" + string(prettyJSON))
	},
}

func init() {
	DeleteAgentCmd.Flags().StringVar(&agentID, "agent-id", "", "ID of the agent to delete")
}
