package deployments

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ListOptions contains options for listing deployments.
type ListOptions struct {
	CustomerFilter string
}

// ListDeployments retrieves and filters the list of MSSP deployments.
// TODO: Replace mock data with actual Nomad/platform queries.
func ListDeployments(rc *eos_io.RuntimeContext, opts ListOptions) (DeploymentList, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing deployments", zap.String("customer_filter", opts.CustomerFilter))

	// Get deployment list
	// TODO: Replace with actual Nomad/platform queries
	deployments := getMockDeployments()

	// Apply filter
	var filtered []DeploymentListItem
	for _, deployment := range deployments {
		if opts.CustomerFilter != "" && deployment.CustomerID != opts.CustomerFilter {
			continue
		}
		filtered = append(filtered, deployment)
	}

	response := DeploymentList{
		Deployments: filtered,
		Total:       len(filtered),
		Summary: DeploymentSummary{
			TotalJobs:      45,
			RunningJobs:    42,
			FailedJobs:     3,
			TotalInstances: 125,
		},
		Timestamp: time.Now(),
	}

	return response, nil
}

// getMockDeployments returns mock deployment data.
// TODO: Replace with actual data source queries.
func getMockDeployments() []DeploymentListItem {
	return []DeploymentListItem{
		{
			JobName:     "wazuh-indexer-cust_12345",
			CustomerID:  "cust_12345",
			CompanyName: "ACME Corporation",
			Type:        "indexer",
			Status:      "running",
			Instances:   3,
			Version:     "4.8.2",
			CPUUsage:    45.2,
			MemoryUsage: 78.5,
			LastUpdated: time.Now().Add(-2 * time.Hour),
		},
		{
			JobName:     "wazuh-server-cust_12345",
			CustomerID:  "cust_12345",
			CompanyName: "ACME Corporation",
			Type:        "server",
			Status:      "running",
			Instances:   2,
			Version:     "4.8.2",
			CPUUsage:    32.1,
			MemoryUsage: 65.3,
			LastUpdated: time.Now().Add(-2 * time.Hour),
		},
		{
			JobName:     "wazuh-dashboard-cust_12345",
			CustomerID:  "cust_12345",
			CompanyName: "ACME Corporation",
			Type:        "dashboard",
			Status:      "running",
			Instances:   1,
			Version:     "4.8.2",
			CPUUsage:    15.7,
			MemoryUsage: 42.1,
			LastUpdated: time.Now().Add(-2 * time.Hour),
		},
	}
}
