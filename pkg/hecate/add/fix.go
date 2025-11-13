// pkg/hecate/add/fix.go - Drift correction for Hecate services

package add

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// FixOptions represents options for fixing service drift/misconfigurations
type FixOptions struct {
	Service string // Service name to fix
	DryRun  bool   // Show what would be fixed without applying
}

// FixService corrects drift and misconfigurations for a service
// This implements the "configuration drift correction" pattern (P0 - CRITICAL)
//
// ARCHITECTURE NOTE: "Fix vs. Create" Distinction
// - eos create <service>: Creates NEW deployment from scratch (canonical state)
// - eos update <service> --fix: Corrects EXISTING deployment back to canonical state
//
// WHAT THIS FIXES:
// - Missing Authentik resources (proxy providers, applications, groups)
// - Incorrect flow configurations (missing invalidation_flow)
// - Mismatched DNS configurations
// - Missing or incorrect group assignments
//
// PATTERN: Assess → Intervene → Evaluate
// 1. ASSESS: Compare current state vs. canonical state
// 2. INTERVENE: Apply fixes (if not dry-run)
// 3. EVALUATE: Verify fixes were successful
func FixService(rc *eos_io.RuntimeContext, opts *FixOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting configuration drift correction",
		zap.String("service", opts.Service),
		zap.Bool("dry_run", opts.DryRun))

	// Check if service has a registered fixer
	fixer, exists := GetServiceFixer(opts.Service)
	if !exists {
		return fmt.Errorf("service '%s' does not support drift correction\n\n"+
			"Supported services:\n"+
			"  - bionicgpt\n"+
			"  - caddy\n\n"+
			"To add support for other services, implement ServiceFixer interface",
			opts.Service)
	}

	// Run the service-specific drift correction
	return fixer.Fix(rc, opts)
}

// ServiceFixer interface for service-specific drift correction
type ServiceFixer interface {
	// Fix corrects drift and misconfigurations for the service
	Fix(rc *eos_io.RuntimeContext, opts *FixOptions) error
}

// serviceFixer registry maps service names to fixer constructors
var serviceFixer = make(map[string]func() ServiceFixer)

// RegisterServiceFixer registers a service fixer constructor
func RegisterServiceFixer(service string, constructor func() ServiceFixer) {
	serviceFixer[service] = constructor
}

// GetServiceFixer retrieves a service fixer (creates new instance)
func GetServiceFixer(service string) (ServiceFixer, bool) {
	constructor, exists := serviceFixer[service]
	if !exists {
		return nil, false
	}
	return constructor(), true
}
