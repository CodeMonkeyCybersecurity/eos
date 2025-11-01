// cmd/read/authentik.go

package read

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/exportutil"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	readAuthentikBaseURL         string
	readAuthentikToken           string
	readAuthentikBlueprintOut    string
	readAuthentikFlowSlug        string
	readAuthentikStageIdentifier string
	readAuthentikStageTypeHint   string
	readAuthentikRawOutput       bool
)

var AuthentikCmd = &cobra.Command{
	Use:   "authentik",
	Short: "Read Authentik resources (flows, stages) or export blueprints",
	Long: `Inspect Authentik resources or export blueprints using credentials discovered
from the local Hecate installation.

Primary operations:
  --flow <slug>          Fetch a flow's full JSON configuration
  --stage <identifier>   Fetch a stage configuration by name or UUID
  (default)              Export Authentik blueprints to YAML

Credentials are resolved in this order:
  1. --ak-url/--ak-token flags (if provided)
  2. AK_URL / AK_TOKEN environment variables
  3. /opt/hecate/.env (AUTHENTIK_* keys) via hecate.DiscoverAuthentikCredentials`,
	RunE: eos.Wrap(runReadAuthentik),
}

func init() {
	AuthentikCmd.Flags().StringVar(&readAuthentikBaseURL, "ak-url", os.Getenv("AK_URL"), "Override Authentik base URL (defaults to Hecate .env)")
	AuthentikCmd.Flags().StringVar(&readAuthentikToken, "ak-token", os.Getenv("AK_TOKEN"), "Override Authentik API token (defaults to Hecate .env)")
	AuthentikCmd.Flags().StringVar(&readAuthentikBlueprintOut, "out", "", "Output path for blueprint export (defaults to timestamped export dir)")
	AuthentikCmd.Flags().StringVar(&readAuthentikFlowSlug, "flow", "", "Flow slug to fetch (returns full JSON definition)")
	AuthentikCmd.Flags().StringVar(&readAuthentikStageIdentifier, "stage", "", "Stage name, slug, or UUID to fetch")
	AuthentikCmd.Flags().StringVar(&readAuthentikStageTypeHint, "stage-type", "", "Optional stage type hint (e.g., identification, password)")
	AuthentikCmd.Flags().BoolVar(&readAuthentikRawOutput, "raw", false, "Print raw JSON without pretty formatting")
}

func runReadAuthentik(rc *eos_io.RuntimeContext, cmd *cobra.Command, _ []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	baseURL, token, err := resolveAuthentikCredentials(rc)
	if err != nil {
		return err
	}

	client := authentik.NewClient(baseURL, token)
	logger.Debug("Authentik client initialised for read command",
		zap.String("base_url", client.BaseURL),
		zap.Bool("flow_requested", readAuthentikFlowSlug != ""),
		zap.Bool("stage_requested", readAuthentikStageIdentifier != ""))

	switch {
	case readAuthentikFlowSlug != "":
		return outputFlowConfig(rc, client, readAuthentikFlowSlug, logger)
	case readAuthentikStageIdentifier != "":
		return outputStageConfig(rc, client, readAuthentikStageIdentifier, readAuthentikStageTypeHint, logger)
	default:
		return exportBlueprints(rc, client, logger)
	}
}

func resolveAuthentikCredentials(rc *eos_io.RuntimeContext) (string, string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	baseURL := strings.TrimSpace(readAuthentikBaseURL)
	token := strings.TrimSpace(readAuthentikToken)

	if baseURL != "" && token != "" {
		return baseURL, token, nil
	}

	// Attempt automatic discovery via Hecate .env
	discoveredToken, discoveredBaseURL, err := hecate.DiscoverAuthentikCredentials(rc)
	if err != nil {
		// If caller explicitly supplied one of the credentials but not the other,
		// surface a helpful error instead of the discovery failure.
		if baseURL == "" || token == "" {
			return "", "", fmt.Errorf("Authentik credentials required: %w", err)
		}
		return "", "", err
	}

	if token == "" {
		token = discoveredToken
	}
	if baseURL == "" {
		baseURL = discoveredBaseURL
	}

	logger.Debug("Authentik credentials discovered from Hecate .env",
		zap.Bool("token_overridden", readAuthentikToken != ""),
		zap.Bool("url_overridden", readAuthentikBaseURL != ""))

	if baseURL == "" || token == "" {
		return "", "", errors.New("Authentik credentials are empty after discovery")
	}

	return baseURL, token, nil
}

func exportBlueprints(rc *eos_io.RuntimeContext, client *authentik.APIClient, logger otelzap.LoggerWithCtx) error {
	data, err := client.ExportBlueprints(rc.Ctx)
	if err != nil {
		return fmt.Errorf("blueprint export failed: %w", err)
	}

	outputPath := readAuthentikBlueprintOut
	if outputPath == "" {
		if err := exportutil.EnsureDir(); err != nil {
			return err
		}
		outputPath, err = exportutil.Build("authentik", "yaml")
		if err != nil {
			return err
		}
	}

	if err := os.WriteFile(outputPath, data, 0o600); err != nil {
		return fmt.Errorf("failed to write blueprints: %w", err)
	}

	logger.Info("Authentik blueprints exported",
		zap.String("file", outputPath),
		zap.Int("bytes", len(data)))
	return nil
}

func outputFlowConfig(rc *eos_io.RuntimeContext, client *authentik.APIClient, slug string, logger otelzap.LoggerWithCtx) error {
	endpoint := fmt.Sprintf("flows/instances/%s/", strings.TrimSpace(slug))
	payload, err := client.APICall(rc.Ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to read flow %q: %w", slug, err)
	}

	logger.Info("Fetched Authentik flow",
		zap.String("slug", slug),
		zap.Int("bytes", len(payload)))

	return printJSON(payload)
}

func outputStageConfig(rc *eos_io.RuntimeContext, client *authentik.APIClient, identifier, typeHint string, logger otelzap.LoggerWithCtx) error {
	stage, stageType, err := client.FindStage(rc.Ctx, identifier, typeHint)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("stages/%s/%s/", stageType, stage.PK)
	payload, err := client.APICall(rc.Ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to read %s stage %q: %w", stageType, identifier, err)
	}

	logger.Info("Fetched Authentik stage",
		zap.String("stage_type", stageType),
		zap.String("stage_pk", stage.PK),
		zap.String("stage_name", stage.Name),
		zap.Int("bytes", len(payload)))

	return printJSON(payload)
}

func printJSON(data []byte) error {
	if readAuthentikRawOutput {
		fmt.Println(string(data))
		return nil
	}

	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		// Fall back to raw if formatting fails
		fmt.Println(string(data))
		return nil
	}

	fmt.Println(pretty.String())
	return nil
}
