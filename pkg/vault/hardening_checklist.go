// pkg/vault/hardening_checklist.go
// Interactive hardening checklist with informed consent
//
// This provides a user-friendly workflow for applying HashiCorp-recommended
// security hardening measures to Vault deployments, with clear explanations
// of each measure's purpose, risk level, and impact.

package vault

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// HardeningStep represents a single security hardening measure
type HardeningStep struct {
	ID          string
	Name        string
	Description string
	Rationale   string // Why this step matters
	ThreatModel string // What threats this mitigates
	Category    string // "required", "recommended", "optional"
	RiskLevel   string // "critical", "high", "medium", "low"
	Enabled     bool   // User's choice
	Applied     bool   // Execution status
	Function    func(*eos_io.RuntimeContext, *api.Client) error
}

// GetHardeningChecklist returns the complete hardening checklist
// organized by HashiCorp's baseline and extended recommendations
func GetHardeningChecklist() []HardeningStep {
	return []HardeningStep{
		// ═══════════════════════════════════════════════════════════
		// BASELINE RECOMMENDATIONS (HashiCorp Production Hardening)
		// ═══════════════════════════════════════════════════════════

		{
			ID:          "audit-dual",
			Name:        "Dual Audit Devices",
			Description: "File + syslog audit for redundancy",
			Rationale:   "Vault stops responding if ALL audit devices fail. Dual devices prevent outages.",
			ThreatModel: "Single audit device failure, forensic gap, compliance violation",
			Category:    "required",
			RiskLevel:   "critical",
			Enabled:     true, // Cannot disable - already done in Phase 6c
			Applied:     true, // Already applied
			Function:    nil,  // Already done in Phase 6c
		},
		{
			ID:          "disable-swap",
			Name:        "Disable Swap",
			Description: "Prevent secrets from being paged to disk",
			Rationale:   "OS can page Vault memory to disk, exposing encryption keys and secrets",
			ThreatModel: "Secrets leaked to disk, cold boot attacks, forensic recovery",
			Category:    "required",
			RiskLevel:   "critical",
			Enabled:     true,
			Function:    func(rc *eos_io.RuntimeContext, _ *api.Client) error { return disableSwap(rc) },
		},
		{
			ID:          "disable-coredumps",
			Name:        "Disable Core Dumps",
			Description: "Prevent memory dumps containing encryption keys",
			Rationale:   "Core dumps can contain Vault's encryption keys in plaintext",
			ThreatModel: "Key exposure via crash dumps, privilege escalation",
			Category:    "required",
			RiskLevel:   "critical",
			Enabled:     true,
			Function:    func(rc *eos_io.RuntimeContext, _ *api.Client) error { return disableCoreDumps(rc) },
		},
		{
			ID:          "security-ulimits",
			Name:        "Security-Focused ulimits",
			Description: "Configure process limits for Vault service",
			Rationale:   "Prevent resource exhaustion attacks and ensure Vault has adequate resources",
			ThreatModel: "Denial of service, resource starvation, file descriptor exhaustion",
			Category:    "required",
			RiskLevel:   "high",
			Enabled:     true,
			Function:    func(rc *eos_io.RuntimeContext, _ *api.Client) error { return setSecurityUlimits(rc) },
		},
		{
			ID:          "log-rotation",
			Name:        "Log Rotation",
			Description: "Prevent audit logs from filling disk",
			Rationale:   "Unrotated logs can fill disk, causing Vault outage (audit write failure)",
			ThreatModel: "Disk full denial of service, audit log loss",
			Category:    "required",
			RiskLevel:   "high",
			Enabled:     true,
			Function:    func(rc *eos_io.RuntimeContext, _ *api.Client) error { return setupLogRotation(rc) },
		},
		{
			ID:          "rate-limiting",
			Name:        "Rate Limiting",
			Description: "Prevent brute force and DoS attacks",
			Rationale:   "Protect against authentication brute force and API flooding",
			ThreatModel: "Brute force attacks, credential stuffing, denial of service",
			Category:    "recommended",
			RiskLevel:   "high",
			Enabled:     true,
			Function:    func(rc *eos_io.RuntimeContext, client *api.Client) error { return enableRateLimiting(rc, client) },
		},

		// ═══════════════════════════════════════════════════════════
		// EXTENDED RECOMMENDATIONS
		// ═══════════════════════════════════════════════════════════

		{
			ID:          "firewall",
			Name:        "Firewall Configuration",
			Description: "Restrict network access to Vault",
			Rationale:   "Limit Vault access to trusted networks only",
			ThreatModel: "Unauthorized network access, port scanning, external attacks",
			Category:    "recommended",
			RiskLevel:   "high",
			Enabled:     true, // Default yes, can opt-out
			Function:    func(rc *eos_io.RuntimeContext, _ *api.Client) error { return configureVaultFirewall(rc) },
		},
		{
			ID:          "backup",
			Name:        "Automated Backups",
			Description: "Daily Raft snapshots with retention",
			Rationale:   "Protect against data loss, enable disaster recovery",
			ThreatModel: "Data loss, corruption, accidental deletion, ransomware",
			Category:    "recommended",
			RiskLevel:   "high",
			Enabled:     true,
			Function:    func(rc *eos_io.RuntimeContext, _ *api.Client) error { return configureVaultBackup(rc) },
		},
		{
			ID:          "ssh-harden",
			Name:        "SSH Hardening",
			Description: "Disable root login, password auth",
			Rationale:   "Protect server access, prevent unauthorized SSH access",
			ThreatModel: "SSH brute force, password attacks, unauthorized access",
			Category:    "recommended",
			RiskLevel:   "medium",
			Enabled:     false, // Default no - can affect other services
			Function:    func(rc *eos_io.RuntimeContext, _ *api.Client) error { return hardenSSH(rc) },
		},
		{
			ID:          "tls-harden",
			Name:        "TLS Hardening",
			Description: "Strong cipher suites, TLS 1.2+ only",
			Rationale:   "Prevent cryptographic attacks on TLS connections",
			ThreatModel: "Man-in-the-middle, downgrade attacks, weak ciphers",
			Category:    "optional",
			RiskLevel:   "medium",
			Enabled:     false, // Requires manual configuration
			Function:    func(rc *eos_io.RuntimeContext, _ *api.Client) error { return hardenTLSConfiguration(rc) },
		},
		{
			ID:          "network-restrict",
			Name:        "Network Restrictions",
			Description: "iptables rules for additional security",
			Rationale:   "Defense in depth beyond firewall",
			ThreatModel: "Network-level attacks, port scanning",
			Category:    "optional",
			RiskLevel:   "medium",
			Enabled:     false, // Can conflict with existing rules
			Function:    func(rc *eos_io.RuntimeContext, _ *api.Client) error { return restrictNetworkAccess(rc) },
		},
	}
}

// InteractiveHardeningWorkflow presents a user-friendly hardening checklist
// and applies selected measures with progress tracking
func InteractiveHardeningWorkflow(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("═══════════════════════════════════════════════════════════════")
	logger.Info(" Vault Security Hardening Checklist")
	logger.Info("═══════════════════════════════════════════════════════════════")
	logger.Info("")
	logger.Info("Based on HashiCorp's Production Hardening Guide:")
	logger.Info("  https://developer.hashicorp.com/vault/docs/concepts/production-hardening")
	logger.Info("")

	// Get hardening checklist
	steps := GetHardeningChecklist()

	// Display checklist organized by category
	displayHardeningChecklist(logger, steps)

	// Ask user if they want to proceed
	logger.Info("")
	logger.Info("terminal prompt: Review the hardening measures above.")
	if !interaction.PromptYesNo(rc.Ctx, "Apply recommended hardening measures?", true) {
		logger.Info("⏭️  Hardening skipped by user")
		logger.Info("")
		logger.Info("IMPORTANT: You can apply hardening later with:")
		logger.Info("  sudo eos update vault --harden")
		logger.Info("")
		return nil
	}

	// Allow user to customize (opt-out of optional measures)
	logger.Info("")
	logger.Info("terminal prompt: You can customize which measures to apply.")
	if interaction.PromptYesNo(rc.Ctx, "Customize hardening options?", false) {
		steps = customizeHardeningSteps(rc, steps)
	}

	// Execute hardening steps
	logger.Info("")
	logger.Info("═══════════════════════════════════════════════════════════════")
	logger.Info(" Applying Hardening Measures")
	logger.Info("═══════════════════════════════════════════════════════════════")
	logger.Info("")

	results := executeHardeningSteps(rc, client, steps)

	// Display results summary
	displayHardeningSummary(logger, results)

	return nil
}

// displayHardeningChecklist shows the hardening measures organized by category
func displayHardeningChecklist(logger otelzap.LoggerWithCtx, steps []HardeningStep) {
	categories := map[string]string{
		"required":    "🔴 REQUIRED (Baseline Security)",
		"recommended": "🟡 RECOMMENDED (Defense in Depth)",
		"optional":    "🟢 OPTIONAL (Advanced Hardening)",
	}

	for _, category := range []string{"required", "recommended", "optional"} {
		logger.Info("")
		logger.Info(categories[category])
		logger.Info(strings.Repeat("─", 63))

		for _, step := range steps {
			if step.Category == category {
				status := "[ ]"
				if step.Enabled {
					status = "[✓]"
				}
				if step.Applied {
					status = "[✓] (already applied)"
				}

				logger.Info(fmt.Sprintf("%s %s", status, step.Name))
				logger.Info(fmt.Sprintf("    %s", step.Description))
				logger.Info(fmt.Sprintf("    Threat: %s", step.ThreatModel))
				if !step.Applied && step.Enabled {
					logger.Info("    → Will be applied")
				}
			}
		}
	}
}

// customizeHardeningSteps allows user to opt-in/opt-out of measures
func customizeHardeningSteps(rc *eos_io.RuntimeContext, steps []HardeningStep) []HardeningStep {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("")
	logger.Info("═══════════════════════════════════════════════════════════════")
	logger.Info(" Customize Hardening Measures")
	logger.Info("═══════════════════════════════════════════════════════════════")
	logger.Info("")

	for i := range steps {
		// Skip already applied measures
		if steps[i].Applied {
			continue
		}

		// Skip required measures (cannot disable)
		if steps[i].Category == "required" {
			continue
		}

		// Prompt for optional/recommended measures
		logger.Info("")
		logger.Info(fmt.Sprintf("── %s ──", steps[i].Name))
		logger.Info(fmt.Sprintf("   %s", steps[i].Description))
		logger.Info(fmt.Sprintf("   Rationale: %s", steps[i].Rationale))
		logger.Info(fmt.Sprintf("   Risk Level: %s", steps[i].RiskLevel))
		logger.Info("")

		steps[i].Enabled = interaction.PromptYesNo(rc.Ctx,
			fmt.Sprintf("Enable %s?", steps[i].Name),
			steps[i].Enabled) // Use current default
	}

	return steps
}

// executeHardeningSteps applies the selected hardening measures
func executeHardeningSteps(rc *eos_io.RuntimeContext, client *api.Client, steps []HardeningStep) []HardeningStep {
	logger := otelzap.Ctx(rc.Ctx)

	for i := range steps {
		// Skip disabled or already applied
		if !steps[i].Enabled || steps[i].Applied || steps[i].Function == nil {
			continue
		}

		logger.Info("")
		logger.Info(fmt.Sprintf("▶ Applying: %s", steps[i].Name))

		startTime := time.Now()
		err := steps[i].Function(rc, client)
		duration := time.Since(startTime)

		if err != nil {
			logger.Warn(fmt.Sprintf("⚠ Failed: %s", steps[i].Name),
				zap.Error(err),
				zap.Duration("duration", duration))

			// Critical measures must succeed
			if steps[i].Category == "required" {
				logger.Error("CRITICAL: Required hardening measure failed",
					zap.String("measure", steps[i].Name),
					zap.String("risk", steps[i].RiskLevel))
				steps[i].Applied = false
			} else {
				// Optional measures can fail
				logger.Info(fmt.Sprintf("  Skipping %s due to error (non-critical)", steps[i].Name))
				steps[i].Applied = false
			}
		} else {
			logger.Info(fmt.Sprintf("✓ Complete: %s", steps[i].Name),
				zap.Duration("duration", duration))
			steps[i].Applied = true
		}
	}

	return steps
}

// displayHardeningSummary shows the final results
func displayHardeningSummary(logger otelzap.LoggerWithCtx, steps []HardeningStep) {
	logger.Info("")
	logger.Info("═══════════════════════════════════════════════════════════════")
	logger.Info(" Hardening Summary")
	logger.Info("═══════════════════════════════════════════════════════════════")
	logger.Info("")

	appliedCount := 0
	failedCount := 0
	skippedCount := 0

	for _, step := range steps {
		if step.Applied {
			appliedCount++
		} else if step.Enabled && step.Function != nil {
			failedCount++
		} else if !step.Enabled && step.Function != nil {
			skippedCount++
		}
	}

	logger.Info(fmt.Sprintf("  ✓ Applied:  %d measures", appliedCount))
	logger.Info(fmt.Sprintf("  ⚠ Failed:   %d measures", failedCount))
	logger.Info(fmt.Sprintf("  ⏭ Skipped:  %d measures", skippedCount))
	logger.Info("")

	if failedCount > 0 {
		logger.Info("⚠ Some hardening measures failed:")
		for _, step := range steps {
			if step.Enabled && !step.Applied && step.Function != nil {
				logger.Warn(fmt.Sprintf("  • %s (%s risk)", step.Name, step.RiskLevel))
			}
		}
		logger.Info("")
	}

	logger.Info("For detailed hardening status, run:")
	logger.Info("  sudo eos read vault --hardening-status")
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("═══════════════════════════════════════════════════════════════")
}
