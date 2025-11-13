package update

import (
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
	updateStageIdentifier    string
	updateStageTypeHint      string
	updateEnrollmentHint     string
	updateRecoveryHint       string
	updateStageDryRun        bool
	updateSkipEnrollmentLink bool
	updateSkipRecoveryLink   bool
)

func init() {
	stageFlowsCmd := &cobra.Command{
		Use:   "stage-flows",
		Short: "Link enrollment and recovery flows to an Authentik stage",
		Long: `Resolve an Authentik stage by name or UUID, locate the associated enrollment
and recovery flows, and patch the stage to reference their UUIDs. Credentials
are discovered automatically from /opt/hecate/.env unless overridden elsewhere.`,
		RunE: eos.Wrap(runUpdateStageFlows),
	}

	stageFlowsCmd.Flags().StringVar(&updateStageIdentifier, "stage", "", "Stage name, slug, or UUID (required)")
	stageFlowsCmd.Flags().StringVar(&updateStageTypeHint, "stage-type", "identification", "Stage type hint used when resolving the stage (default: identification)")
	stageFlowsCmd.Flags().StringVar(&updateEnrollmentHint, "enrollment-flow", "", "Enrollment flow slug or substring (auto-detected if empty)")
	stageFlowsCmd.Flags().StringVar(&updateRecoveryHint, "recovery-flow", "", "Recovery flow slug or substring (auto-detected if empty)")
	stageFlowsCmd.Flags().BoolVar(&updateStageDryRun, "dry-run", false, "Show planned updates without applying changes")
	stageFlowsCmd.Flags().BoolVar(&updateSkipEnrollmentLink, "skip-enrollment", false, "Skip linking an enrollment flow")
	stageFlowsCmd.Flags().BoolVar(&updateSkipRecoveryLink, "skip-recovery", false, "Skip linking a recovery flow")

	updateAuthentikCmd.AddCommand(stageFlowsCmd)
}

func runUpdateStageFlows(rc *eos_io.RuntimeContext, cmd *cobra.Command, _ []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if strings.TrimSpace(updateStageIdentifier) == "" {
		return fmt.Errorf("--stage is required")
	}

	token, baseURL, err := hecate.DiscoverAuthentikCredentials(rc)
	if err != nil {
		return fmt.Errorf("failed to load Authentik credentials: %w", err)
	}

	client := authentik.NewClient(baseURL, token)

	stage, stageType, err := client.FindStage(rc.Ctx, updateStageIdentifier, updateStageTypeHint)
	if err != nil {
		return fmt.Errorf("failed to resolve stage: %w", err)
	}

	logger.Info("Stage resolved",
		zap.String("stage_pk", stage.PK),
		zap.String("stage_name", stage.Name),
		zap.String("stage_type", stageType))

	updates := make(map[string]interface{})

	if !updateSkipEnrollmentLink {
		enrollmentFlow, err := resolveFlowByHint(rc, client, "enrollment", stage, updateStageIdentifier, updateEnrollmentHint)
		if err != nil {
			return err
		}
		if enrollmentFlow != nil {
			updates["enrollment_flow"] = enrollmentFlow.PK
			logger.Info("Enrollment flow resolved",
				zap.String("slug", enrollmentFlow.Slug),
				zap.String("uuid", enrollmentFlow.PK))
		}
	}

	if !updateSkipRecoveryLink {
		recoveryFlow, err := resolveFlowByHint(rc, client, "recovery", stage, updateStageIdentifier, updateRecoveryHint)
		if err != nil {
			return err
		}
		if recoveryFlow != nil {
			updates["recovery_flow"] = recoveryFlow.PK
			logger.Info("Recovery flow resolved",
				zap.String("slug", recoveryFlow.Slug),
				zap.String("uuid", recoveryFlow.PK))
		}
	}

	if len(updates) == 0 {
		return fmt.Errorf("no updates to apply (consider removing skip flags or providing flow hints)")
	}

	if updateStageDryRun {
		fmt.Println("[dry-run] Would update stage with:")
		for key, value := range updates {
			fmt.Printf("  %s: %v\n", key, value)
		}
		return nil
	}

	if err := client.UpdateStage(rc.Ctx, stageType, stage.PK, updates); err != nil {
		return fmt.Errorf("stage update failed: %w", err)
	}

	fmt.Printf("Stage %s (%s) updated.\n", stage.Name, stage.PK)
	return nil
}

func resolveFlowByHint(rc *eos_io.RuntimeContext, client *authentik.APIClient, designation string, stage *authentik.StageResponse, identifierHint, userHint string) (*authentik.FlowResponse, error) {
	hints := buildFlowHints(stage, identifierHint, userHint, designation)

	flows, err := client.ListFlows(rc.Ctx, designation)
	if err != nil {
		return nil, fmt.Errorf("failed to list %s flows: %w", designation, err)
	}

	if len(flows) == 0 {
		return nil, fmt.Errorf("no flows with designation %s found", designation)
	}

	sort.Slice(flows, func(i, j int) bool { return flows[i].Slug < flows[j].Slug })

	for _, hint := range hints {
		if hint == "" {
			continue
		}
		for i := range flows {
			flow := flows[i]
			if strings.EqualFold(flow.Slug, hint) || strings.EqualFold(flow.Name, hint) || strings.EqualFold(flow.PK, hint) {
				return &flows[i], nil
			}
		}
	}

	for _, hint := range hints {
		if hint == "" {
			continue
		}
		needle := strings.ToLower(hint)
		for i := range flows {
			flow := flows[i]
			if strings.Contains(strings.ToLower(flow.Slug), needle) || strings.Contains(strings.ToLower(flow.Name), needle) {
				return &flows[i], nil
			}
		}
	}

	// Fallback: return the first flow of the requested designation
	return &flows[0], nil
}

func buildFlowHints(stage *authentik.StageResponse, identifierHint, userHint, target string) []string {
	target = strings.ToLower(target)
	hints := make([]string, 0, 6)

	appendHint := func(value string) {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			return
		}
		for _, existing := range hints {
			if existing == value {
				return
			}
		}
		hints = append(hints, value)
	}

	appendHint(userHint)

	if stage != nil {
		appendHint(stage.Name)
		appendHint(stage.VerboseName)
	}

	appendHint(identifierHint)

	normalized := strings.ToLower(identifierHint)
	normalized = strings.TrimSuffix(normalized, "-identification")
	normalized = strings.TrimSuffix(normalized, "-stage")
	normalized = strings.TrimSuffix(normalized, "-prompt")

	if strings.Contains(normalized, "authentication") {
		appendHint(strings.Replace(normalized, "authentication", target, 1))
	}
	if strings.Contains(normalized, "auth") {
		appendHint(strings.Replace(normalized, "auth", target, 1))
	}

	if normalized != "" {
		appendHint(normalized + "-" + target)
	}

	appendHint(target)

	return hints
}
