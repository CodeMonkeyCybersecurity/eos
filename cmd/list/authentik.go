package list

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	listAllDetails        bool
	listJSONOutput        bool
	listDesignationFilter string
	listContainsFilter    string
	listFlowSlugFilter    string
	listStageBindingsSlug string
)

// AuthentikCmd represents `eos ls authentik`
var AuthentikCmd = &cobra.Command{
	Use:   "authentik [flows|stage-bindings] [slug]",
	Short: "Inspect Authentik flows, bindings, and related metadata",
	Long: `Inspect Authentik flows and their stage bindings using the credentials
discovered from the local Hecate .env (AUTHENTIK_* variables).

Examples:
  eos ls authentik --all flows
  eos ls authentik --flows              # default action, lists all flows
  eos ls authentik flows bionicgpt-authentication
  eos ls authentik --stage-bindings default-authentication-flow
  eos ls authentik stage-bindings bionicgpt-authentication`,
	RunE: eos.Wrap(runListAuthentik),
}

func init() {
	authentikFlags := AuthentikCmd.Flags()
	authentikFlags.BoolVar(&listAllDetails, "all", false, "Show extended details (includes UUIDs, policies)")
	authentikFlags.BoolVar(&listJSONOutput, "json", false, "Output raw JSON response")
	authentikFlags.StringVar(&listDesignationFilter, "designation", "", "Filter flows by designation (authentication, enrollment, recovery, etc.)")
	authentikFlags.StringVar(&listContainsFilter, "contains", "", "Filter flows whose slug or name contains the provided substring")
	authentikFlags.StringVar(&listFlowSlugFilter, "flow", "", "Filter flows by exact slug (default action)")
	authentikFlags.StringVar(&listStageBindingsSlug, "stage-bindings", "", "Flow slug to list stage bindings for")

	ListCmd.AddCommand(AuthentikCmd)
}

func runListAuthentik(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	action := determineAuthentikListAction(args)
	stageSlug := listStageBindingsSlug
	flowSlug := listFlowSlugFilter

	// Allow positional slug filters
	if len(args) > 0 {
		switch action {
		case "flows":
			if len(args) > 1 && flowSlug == "" {
				flowSlug = args[1]
			} else if len(args) == 1 && !isKnownKeyword(args[0]) && flowSlug == "" {
				flowSlug = args[0]
			}
		case "stage-bindings":
			if len(args) > 1 && stageSlug == "" {
				stageSlug = args[1]
			} else if len(args) == 1 && stageSlug == "" && !isKnownKeyword(args[0]) {
				stageSlug = args[0]
			}
		}
	}

	// If stage bindings slug not provided, reuse flow slug where it makes sense
	if stageSlug == "" && action == "stage-bindings" {
		stageSlug = flowSlug
	}

	token, baseURL, err := hecate.DiscoverAuthentikCredentials(rc)
	if err != nil {
		return fmt.Errorf("failed to load Authentik credentials: %w", err)
	}

	client := authentik.NewClient(baseURL, token)
	logger.Debug("Authentik client initialized for list command",
		zap.String("base_url", client.BaseURL),
		zap.String("action", action))

	switch action {
	case "stage-bindings":
		if stageSlug == "" {
			return fmt.Errorf("flow slug required: provide --stage-bindings <slug> or positional slug")
		}
		return outputStageBindings(rc, client, stageSlug, logger)
	default:
		return outputFlows(rc, client, flowSlug, logger)
	}
}

func determineAuthentikListAction(args []string) string {
	if listStageBindingsSlug != "" {
		return "stage-bindings"
	}
	if len(args) == 0 {
		return "flows"
	}

	switch strings.ToLower(args[0]) {
	case "stage-bindings", "bindings":
		return "stage-bindings"
	case "flows":
		return "flows"
	default:
		// Default to flows when we can't infer action - positional could be a slug filter
		return "flows"
	}
}

func isKnownKeyword(arg string) bool {
	switch strings.ToLower(arg) {
	case "flows", "stage-bindings", "bindings":
		return true
	default:
		return false
	}
}

func outputFlows(rc *eos_io.RuntimeContext, client *authentik.APIClient, slug string, logger otelzap.LoggerWithCtx) error {
	flows, err := client.ListFlows(rc.Ctx, listDesignationFilter)
	if err != nil {
		return fmt.Errorf("failed to list flows: %w", err)
	}

	filtered := filterFlows(flows, slug, listContainsFilter)

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Designation == filtered[j].Designation {
			return filtered[i].Slug < filtered[j].Slug
		}
		return filtered[i].Designation < filtered[j].Designation
	})

	if listJSONOutput {
		data, err := json.MarshalIndent(filtered, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to serialize flows: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	if len(filtered) == 0 {
		if slug != "" || listContainsFilter != "" {
			fmt.Printf("No flows match slug=%q contains=%q designation=%q\n", slug, listContainsFilter, listDesignationFilter)
		} else {
			fmt.Println("No flows found.")
		}
		return nil
	}

	for _, flow := range filtered {
		if listAllDetails {
			fmt.Printf("%s (%s)\n", flow.Name, flow.Slug)
			fmt.Printf("  designation: %s\n", flow.Designation)
			fmt.Printf("  uuid:        %s\n", flow.PK)
			fmt.Printf("  denied_action: %s\n", zeroOrValue(flow.DeniedAction, "not set"))
			fmt.Println()
		} else {
			fmt.Printf("%s - %s - designation: %s\n", flow.Slug, flow.Name, flow.Designation)
		}
	}

	logger.Info("Listed Authentik flows",
		zap.Int("count", len(filtered)),
		zap.String("designation", listDesignationFilter),
		zap.String("slug_filter", slug),
		zap.String("contains", listContainsFilter))

	return nil
}

func filterFlows(flows []authentik.FlowResponse, slugFilter, containsFilter string) []authentik.FlowResponse {
	if slugFilter == "" && containsFilter == "" {
		return flows
	}

	contains := strings.ToLower(containsFilter)
	filtered := make([]authentik.FlowResponse, 0, len(flows))

	for _, flow := range flows {
		if slugFilter != "" && !strings.EqualFold(flow.Slug, slugFilter) {
			continue
		}
		if contains != "" {
			if !strings.Contains(strings.ToLower(flow.Slug), contains) &&
				!strings.Contains(strings.ToLower(flow.Name), contains) {
				continue
			}
		}
		filtered = append(filtered, flow)
	}

	return filtered
}

func outputStageBindings(rc *eos_io.RuntimeContext, client *authentik.APIClient, slug string, logger otelzap.LoggerWithCtx) error {
	flow, err := client.GetFlow(rc.Ctx, slug)
	if err != nil {
		return fmt.Errorf("failed to resolve flow %q: %w", slug, err)
	}
	if flow == nil {
		return fmt.Errorf("flow %q not found", slug)
	}

	bindings, err := client.ListFlowBindings(rc.Ctx, flow.PK)
	if err != nil {
		return fmt.Errorf("failed to list stage bindings for %q: %w", slug, err)
	}

	sort.Slice(bindings, func(i, j int) bool {
		if bindings[i].Order == bindings[j].Order {
			return bindings[i].PK < bindings[j].PK
		}
		return bindings[i].Order < bindings[j].Order
	})

	if listJSONOutput {
		data, err := json.MarshalIndent(bindings, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to serialize stage bindings: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	if len(bindings) == 0 {
		fmt.Printf("Flow %s (%s) has no stage bindings.\n", flow.Name, flow.Slug)
		return nil
	}

	fmt.Printf("Stage bindings for %s (%s)\n", flow.Name, flow.Slug)
	for _, binding := range bindings {
		stageName, stageComponent := stageMetadata(binding.StageObj)
		fmt.Printf("  %2d. %s (%s)\n", binding.Order, stageName, stageComponent)
		if listAllDetails {
			fmt.Printf("      binding_uuid: %s\n", binding.PK)
			fmt.Printf("      stage_uuid:   %s\n", binding.Stage)
			if len(binding.PolicyBindings) > 0 {
				fmt.Printf("      policies:\n")
				for _, policy := range binding.PolicyBindings {
					fmt.Printf("        - pk: %s (enabled=%t negate=%t order=%d)\n",
						policy.PK, policy.Enabled, policy.Negate, policy.Order)
				}
			}
		}
	}

	logger.Info("Listed Authentik stage bindings",
		zap.Int("count", len(bindings)),
		zap.String("flow_slug", flow.Slug),
		zap.String("flow_uuid", flow.PK))

	return nil
}

func stageMetadata(stage *authentik.StageResponse) (string, string) {
	if stage == nil {
		return "unknown stage", "unknown"
	}
	name := stage.Name
	if name == "" {
		name = "unnamed"
	}
	component := stage.Component
	if component == "" {
		component = stage.Type
	}
	if component == "" {
		component = "unknown"
	}
	return name, component
}

func zeroOrValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
