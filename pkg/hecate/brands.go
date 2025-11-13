package hecate

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ListAuthentikBrands retrieves all Authentik brands using the standard Hecate credential discovery flow.
func ListAuthentikBrands(rc *eos_io.RuntimeContext) ([]authentik.BrandResponse, error) {
	logger := otelzap.Ctx(rc.Ctx)

	token, baseURL, err := discoverAuthentikCredentials(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to discover Authentik credentials: %w", err)
	}

	client := authentik.NewClient(baseURL, token)

	logger.Debug("Listing Authentik brands",
		zap.String("base_url", client.BaseURL))

	brands, err := client.ListBrands(rc.Ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list Authentik brands: %w", err)
	}

	return brands, nil
}
