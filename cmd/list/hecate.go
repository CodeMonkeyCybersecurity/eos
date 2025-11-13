package list

import (
	"fmt"
	"sort"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var listHecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "List Hecate resources and Authentik integrations",
	Long: `Inspect Hecate-managed integrations.

Use --brands to list Authentik brands and their associated authentication flows.`,
	RunE: eos_cli.Wrap(runListHecate),
}

func init() {
	ListCmd.AddCommand(listHecateCmd)

	listHecateCmd.Flags().Bool("brands", false, "List Authentik brands configured for Hecate")
}

func runListHecate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	showBrands, _ := cmd.Flags().GetBool("brands")

	switch {
	case showBrands:
		return runListHecateBrands(rc)
	default:
		logger.Info("No listing option provided. Use --brands to list Authentik brands.")
		return cmd.Help()
	}
}

func runListHecateBrands(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	brands, err := hecate.ListAuthentikBrands(rc)
	if err != nil {
		return err
	}

	if len(brands) == 0 {
		logger.Info("terminal prompt: No Authentik brands found")
		return nil
	}

	sort.Slice(brands, func(i, j int) bool {
		return strings.ToLower(brands[i].Domain) < strings.ToLower(brands[j].Domain)
	})

	logger.Info("terminal prompt: Authentik Brands")
	logger.Info("terminal prompt: " + strings.Repeat("=", 60))
	logger.Info("terminal prompt: Domain                           Flow Authentication")
	logger.Info("terminal prompt: " + strings.Repeat("-", 60))

	for _, brand := range brands {
		domain := brand.Domain
		if domain == "" {
			domain = "(no domain)"
		}

		flow := brand.FlowAuthentication
		if flow == "" {
			flow = "-"
		}

		logger.Info(fmt.Sprintf("terminal prompt: %-30s  %s", domain, flow),
			zap.String("brand_uuid", brand.PK),
			zap.String("flow_invalidation", brand.FlowInvalidation))
	}

	return nil
}
