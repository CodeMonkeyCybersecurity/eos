// pkg/authentik/extract_helper.go

package authentik

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ExtractConfigurationAPI extracts Authentik configuration via API
func ExtractConfigurationAPI(ctx context.Context, baseURL, token string, types, apps, providers []string, includeSecrets bool) (*AuthentikConfig, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	config := &AuthentikConfig{
		Metadata: ConfigMetadata{
			ExportedAt: time.Now(),
			SourceURL:  baseURL,
			ExportedBy: "",
		},
		Providers:        []Provider{},
		Applications:     []Application{},
		PropertyMappings: []PropertyMapping{},
		Flows:            []Flow{},
		Stages:           []Stage{},
		Groups:           []Group{},
		Policies:         []Policy{},
		Certificates:     []Certificate{},
	}

	// Helper function to make API calls
	makeAPICall := func(endpoint string) ([]byte, error) {
		url := fmt.Sprintf("%s/api/v3/%s", strings.TrimSuffix(baseURL, "/"), endpoint)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("API request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
		}

		return io.ReadAll(resp.Body)
	}

	// Track extraction errors
	var extractionErrors []error
	successfulExtractions := 0

	// Extract each type requested
	for _, resourceType := range types {
		switch strings.ToLower(resourceType) {
		case "providers":
			data, err := makeAPICall("providers/all/")
			if err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("providers: %w", err))
				continue
			}
			var result struct {
				Results []Provider `json:"results"`
			}
			if err := json.Unmarshal(data, &result); err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("providers unmarshal: %w", err))
				continue
			}
			config.Providers = filterProviders(result.Results, providers)
			successfulExtractions++

		case "applications":
			data, err := makeAPICall("core/applications/")
			if err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("applications: %w", err))
				continue
			}
			var result struct {
				Results []Application `json:"results"`
			}
			if err := json.Unmarshal(data, &result); err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("applications unmarshal: %w", err))
				continue
			}
			config.Applications = filterApplications(result.Results, apps)
			successfulExtractions++

		case "mappings", "property_mappings":
			data, err := makeAPICall("propertymappings/all/")
			if err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("property mappings: %w", err))
				continue
			}
			var result struct {
				Results []json.RawMessage `json:"results"`
			}
			if err := json.Unmarshal(data, &result); err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("property mappings unmarshal: %w", err))
				continue
			}
			// Parse SAML property mappings specifically
			for _, raw := range result.Results {
				var mapping PropertyMapping
				if err := json.Unmarshal(raw, &mapping); err == nil {
					config.PropertyMappings = append(config.PropertyMappings, mapping)
				}
			}
			successfulExtractions++

		case "flows":
			data, err := makeAPICall("flows/instances/")
			if err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("flows: %w", err))
				continue
			}
			var result struct {
				Results []Flow `json:"results"`
			}
			if err := json.Unmarshal(data, &result); err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("flows unmarshal: %w", err))
				continue
			}
			config.Flows = result.Results
			successfulExtractions++

		case "stages":
			data, err := makeAPICall("stages/all/")
			if err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("stages: %w", err))
				continue
			}
			var result struct {
				Results []Stage `json:"results"`
			}
			if err := json.Unmarshal(data, &result); err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("stages unmarshal: %w", err))
				continue
			}
			config.Stages = result.Results
			successfulExtractions++

		case "groups":
			data, err := makeAPICall("core/groups/")
			if err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("groups: %w", err))
				continue
			}
			var result struct {
				Results []Group `json:"results"`
			}
			if err := json.Unmarshal(data, &result); err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("groups unmarshal: %w", err))
				continue
			}
			config.Groups = result.Results
			successfulExtractions++

		case "policies":
			data, err := makeAPICall("policies/all/")
			if err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("policies: %w", err))
				continue
			}
			var result struct {
				Results []Policy `json:"results"`
			}
			if err := json.Unmarshal(data, &result); err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("policies unmarshal: %w", err))
				continue
			}
			config.Policies = result.Results
			successfulExtractions++

		case "certificates":
			endpoint := "crypto/certificatekeypairs/"
			if !includeSecrets {
				endpoint += "?exclude_key=true"
			}
			data, err := makeAPICall(endpoint)
			if err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("certificates: %w", err))
				continue
			}
			var result struct {
				Results []Certificate `json:"results"`
			}
			if err := json.Unmarshal(data, &result); err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("certificates unmarshal: %w", err))
				continue
			}
			config.Certificates = result.Results
			successfulExtractions++

		case "blueprints":
			data, err := makeAPICall("managed/blueprints/")
			if err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("blueprints: %w", err))
				continue
			}
			var result struct {
				Results []Blueprint `json:"results"`
			}
			if err := json.Unmarshal(data, &result); err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("blueprints unmarshal: %w", err))
				continue
			}
			config.Blueprints = result.Results
			successfulExtractions++

		case "outposts":
			data, err := makeAPICall("outposts/instances/")
			if err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("outposts: %w", err))
				continue
			}
			var result struct {
				Results []Outpost `json:"results"`
			}
			if err := json.Unmarshal(data, &result); err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("outposts unmarshal: %w", err))
				continue
			}
			config.Outposts = result.Results
			successfulExtractions++

		case "tenants":
			data, err := makeAPICall("core/tenants/")
			if err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("tenants: %w", err))
				continue
			}
			var result struct {
				Results []Tenant `json:"results"`
			}
			if err := json.Unmarshal(data, &result); err != nil {
				extractionErrors = append(extractionErrors, fmt.Errorf("tenants unmarshal: %w", err))
				continue
			}
			config.Tenants = result.Results
			successfulExtractions++
		}
	}

	// Try to get version info (non-critical)
	if data, err := makeAPICall("admin/version/"); err == nil {
		var versionInfo struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(data, &versionInfo); err == nil {
			config.Metadata.AuthentikVersion = versionInfo.Version
		}
	}

	// If ALL extractions failed, return error with details
	if successfulExtractions == 0 && len(extractionErrors) > 0 {
		errorMsg := fmt.Sprintf("failed to extract any configuration (attempted %d types):\n", len(types))
		for _, err := range extractionErrors {
			errorMsg += fmt.Sprintf("  - %s\n", err.Error())
		}
		errorMsg += "\nCommon causes:\n"
		errorMsg += "  - Invalid URL (check for typos like 'https://https://')\n"
		errorMsg += "  - Invalid or expired API token\n"
		errorMsg += "  - Network connectivity issues\n"
		errorMsg += "  - Authentik API not accessible at provided URL"
		return nil, fmt.Errorf(errorMsg)
	}

	// If SOME extractions failed, include warnings but return partial success
	if len(extractionErrors) > 0 {
		// Note: Caller should log these as warnings
		// For now, we return partial success
	}

	return config, nil
}

// filterProviders filters providers by name if a filter list is provided
func filterProviders(providers []Provider, filter []string) []Provider {
	if len(filter) == 0 {
		return providers
	}

	filtered := []Provider{}
	filterMap := make(map[string]bool)
	for _, name := range filter {
		filterMap[strings.ToLower(name)] = true
	}

	for _, provider := range providers {
		if filterMap[strings.ToLower(provider.Name)] {
			filtered = append(filtered, provider)
		}
	}
	return filtered
}

// filterApplications filters applications by name if a filter list is provided
func filterApplications(apps []Application, filter []string) []Application {
	if len(filter) == 0 {
		return apps
	}

	filtered := []Application{}
	filterMap := make(map[string]bool)
	for _, name := range filter {
		filterMap[strings.ToLower(name)] = true
	}

	for _, app := range apps {
		lowerName := strings.ToLower(app.Name)
		lowerSlug := strings.ToLower(app.Slug)
		if filterMap[lowerName] || filterMap[lowerSlug] {
			filtered = append(filtered, app)
		}
	}
	return filtered
}