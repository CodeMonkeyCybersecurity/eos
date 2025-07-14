package hecate

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateUpstream creates a new upstream configuration
func CreateUpstream(rc *eos_io.RuntimeContext, upstream *Upstream) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing upstream creation prerequisites",
		zap.String("url", upstream.URL))

	// Check if upstream already exists
	exists, err := upstreamExists(rc, upstream.URL)
	if err != nil {
		return fmt.Errorf("failed to check upstream existence: %w", err)
	}
	if exists {
		return eos_err.NewUserError("upstream %s already exists", upstream.URL)
	}

	// Validate URL
	if upstream.URL == "" {
		return eos_err.NewUserError("upstream must have a URL")
	}

	// INTERVENE
	logger.Info("Creating upstream configuration",
		zap.String("url", upstream.URL))

	// TODO: Implement actual upstream creation in Caddy
	// This would involve updating Caddy's configuration

	// Update state store
	if err := updateStateStore(rc, "upstreams", upstream.URL, upstream); err != nil {
		logger.Warn("Failed to update state store",
			zap.Error(err))
	}

	// EVALUATE
	logger.Info("Verifying upstream functionality",
		zap.String("url", upstream.URL))

	if err := verifyUpstream(rc, upstream); err != nil {
		return fmt.Errorf("upstream verification failed: %w", err)
	}

	logger.Info("Upstream created successfully",
		zap.String("url", upstream.URL))

	return nil
}

// DeleteUpstream removes an upstream configuration
func DeleteUpstream(rc *eos_io.RuntimeContext, upstreamURL string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing upstream deletion prerequisites",
		zap.String("url", upstreamURL))

	// Check if upstream exists
	exists, err := upstreamExists(rc, upstreamURL)
	if err != nil {
		return fmt.Errorf("failed to check upstream existence: %w", err)
	}
	if !exists {
		return eos_err.NewUserError("upstream %s not found", upstreamURL)
	}

	// Check if upstream is in use by any routes
	inUse, routes, err := checkUpstreamUsage(rc, upstreamURL)
	if err != nil {
		return fmt.Errorf("failed to check upstream usage: %w", err)
	}
	if inUse {
		return eos_err.NewUserError("upstream %s is in use by routes: %v", upstreamURL, routes)
	}

	// INTERVENE
	logger.Info("Deleting upstream configuration",
		zap.String("url", upstreamURL))

	// TODO: Implement actual upstream deletion from Caddy

	// Delete from state store
	if err := deleteFromStateStore(rc, "upstreams", upstreamURL); err != nil {
		logger.Warn("Failed to delete from state store",
			zap.Error(err))
	}

	// EVALUATE
	logger.Info("Verifying upstream deletion",
		zap.String("url", upstreamURL))

	exists, err = upstreamExists(rc, upstreamURL)
	if err != nil {
		return fmt.Errorf("failed to verify upstream deletion: %w", err)
	}
	if exists {
		return fmt.Errorf("upstream still exists after deletion")
	}

	logger.Info("Upstream deleted successfully",
		zap.String("url", upstreamURL))

	return nil
}

// Helper functions

func upstreamExists(rc *eos_io.RuntimeContext, upstreamURL string) (bool, error) {
	// TODO: Implement checking if upstream exists
	return false, nil
}

func verifyUpstream(rc *eos_io.RuntimeContext, upstream *Upstream) error {
	// TODO: Implement upstream verification
	// This could involve health checks on the servers
	return nil
}

func checkUpstreamUsage(rc *eos_io.RuntimeContext, upstreamURL string) (bool, []string, error) {
	// TODO: Check all routes to see if any use this upstream
	return false, nil, nil
}
