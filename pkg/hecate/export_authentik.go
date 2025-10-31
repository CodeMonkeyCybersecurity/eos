// pkg/hecate/export_authentik.go - Export Authentik configuration for Hecate observability

package hecate

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AuthentikConfigReport represents a complete snapshot of Authentik configuration
type AuthentikConfigReport struct {
	Brands       []authentik.BrandResponse
	Flows        []authentik.FlowResponse
	Stages       []authentik.StageResponse
	Groups       []authentik.GroupResponse
	Applications []authentik.ApplicationResponse
	// FlowDetails maps flow PK to its stage bindings
	FlowDetails map[string][]authentik.StageBindingResponse
}

// ExportAuthentikConfig exports the complete Authentik configuration for observability
// P0 OBSERVABILITY: Enables users to see what self-enrollment has configured
func ExportAuthentikConfig(rc *eos_io.RuntimeContext, authentikURL, apiToken string) (*AuthentikConfigReport, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Exporting Authentik configuration",
		zap.String("authentik_url", authentikURL))

	// Create Authentik API client
	authentikClient := authentik.NewClient(authentikURL, apiToken)

	report := &AuthentikConfigReport{
		FlowDetails: make(map[string][]authentik.StageBindingResponse),
	}

	// Fetch brands
	logger.Info("Fetching brands configuration")
	brands, err := authentikClient.ListBrands(rc.Ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list brands: %w", err)
	}
	report.Brands = brands
	logger.Info("✓ Brands fetched", zap.Int("count", len(brands)))

	// Fetch flows
	logger.Info("Fetching flows configuration")
	flows, err := authentikClient.ListFlows(rc.Ctx, "") // All designations
	if err != nil {
		return nil, fmt.Errorf("failed to list flows: %w", err)
	}
	report.Flows = flows
	logger.Info("✓ Flows fetched", zap.Int("count", len(flows)))

	// Fetch flow details (stages for each flow)
	logger.Info("Fetching stage bindings for each flow")
	for _, flow := range flows {
		bindings, err := authentikClient.GetFlowStages(rc.Ctx, flow.PK)
		if err != nil {
			logger.Warn("Failed to fetch stages for flow",
				zap.String("flow_slug", flow.Slug),
				zap.Error(err))
			continue
		}
		report.FlowDetails[flow.PK] = bindings
	}
	logger.Info("✓ Stage bindings fetched")

	// Fetch stages
	logger.Info("Fetching stages configuration")
	stages, err := authentikClient.ListStages(rc.Ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list stages: %w", err)
	}
	report.Stages = stages
	logger.Info("✓ Stages fetched", zap.Int("count", len(stages)))

	// Fetch groups
	logger.Info("Fetching groups configuration")
	groups, err := authentikClient.ListGroups(rc.Ctx, "") // All groups
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}
	report.Groups = groups
	logger.Info("✓ Groups fetched", zap.Int("count", len(groups)))

	// Fetch applications
	logger.Info("Fetching applications configuration")
	applications, err := authentikClient.ListApplications(rc.Ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list applications: %w", err)
	}
	report.Applications = applications
	logger.Info("✓ Applications fetched", zap.Int("count", len(applications)))

	logger.Info("✓ Authentik configuration export complete")
	return report, nil
}

// FormatAuthentikReport formats the configuration report for human-readable display
func FormatAuthentikReport(report *AuthentikConfigReport) string {
	var sb strings.Builder

	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString("Authentik Configuration Report\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	// Brands section
	sb.WriteString(fmt.Sprintf("BRANDS (%d)\n", len(report.Brands)))
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	for _, brand := range report.Brands {
		sb.WriteString(fmt.Sprintf("  • %s\n", brand.BrandingTitle))
		sb.WriteString(fmt.Sprintf("    Domain: %s\n", brand.Domain))
		sb.WriteString(fmt.Sprintf("    Brand UUID: %s\n", brand.PK))
		if brand.FlowEnrollment != "" {
			sb.WriteString(fmt.Sprintf("    Enrollment Flow: %s ✓\n", brand.FlowEnrollment))
		} else {
			sb.WriteString("    Enrollment Flow: Not configured\n")
		}
		sb.WriteString("\n")
	}

	// Flows section
	sb.WriteString(fmt.Sprintf("FLOWS (%d)\n", len(report.Flows)))
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	// Group flows by designation
	flowsByDesignation := make(map[string][]authentik.FlowResponse)
	for _, flow := range report.Flows {
		flowsByDesignation[flow.Designation] = append(flowsByDesignation[flow.Designation], flow)
	}

	for designation, flows := range flowsByDesignation {
		sb.WriteString(fmt.Sprintf("\n  %s FLOWS:\n", strings.ToUpper(designation)))
		for _, flow := range flows {
			sb.WriteString(fmt.Sprintf("    • %s (%s)\n", flow.Title, flow.Slug))

			// Show stages for this flow
			if bindings, ok := report.FlowDetails[flow.PK]; ok {
				sb.WriteString(fmt.Sprintf("      Stages: %d\n", len(bindings)))
				for i, binding := range bindings {
					sb.WriteString(fmt.Sprintf("        %d. Stage PK: %s\n", i+1, binding.Stage))
				}
			}
			sb.WriteString("\n")
		}
	}

	// Groups section
	sb.WriteString(fmt.Sprintf("GROUPS (%d)\n", len(report.Groups)))
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	for _, group := range report.Groups {
		sb.WriteString(fmt.Sprintf("  • %s\n", group.Name))
		if group.IsSuperuser {
			sb.WriteString("    Role: Superuser\n")
		} else {
			sb.WriteString("    Role: Standard user\n")
		}
		if attrs, ok := group.Attributes["eos_managed"].(bool); ok && attrs {
			sb.WriteString("    Managed by: Eos ✓\n")
		}
		sb.WriteString("\n")
	}

	// Stages section
	sb.WriteString(fmt.Sprintf("STAGES (%d)\n", len(report.Stages)))
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	// Group stages by type
	stagesByType := make(map[string][]authentik.StageResponse)
	for _, stage := range report.Stages {
		stagesByType[stage.VerboseName] = append(stagesByType[stage.VerboseName], stage)
	}

	for stageType, stages := range stagesByType {
		sb.WriteString(fmt.Sprintf("\n  %s:\n", stageType))
		for _, stage := range stages {
			sb.WriteString(fmt.Sprintf("    • %s\n", stage.Name))
		}
	}
	sb.WriteString("\n")

	// Applications section
	sb.WriteString(fmt.Sprintf("APPLICATIONS (%d)\n", len(report.Applications)))
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	for _, app := range report.Applications {
		sb.WriteString(fmt.Sprintf("  • %s (%s)\n", app.Name, app.Slug))
		if app.Provider != 0 {
			sb.WriteString(fmt.Sprintf("    Provider PK: %d", app.Provider))
			if app.ProviderObj.Name != "" {
				sb.WriteString(fmt.Sprintf(" (%s)", app.ProviderObj.Name))
			}
			sb.WriteString("\n")
		}
		if app.MetaLaunchURL != "" {
			sb.WriteString(fmt.Sprintf("    Launch URL: %s\n", app.MetaLaunchURL))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	return sb.String()
}
