// Package deployments provides Wazuh MSSP deployment management functionality.
package deployments

import "time"

// DeploymentListItem represents a single deployment in the MSSP platform.
type DeploymentListItem struct {
	JobName     string    `json:"job_name"`
	CustomerID  string    `json:"customer_id"`
	CompanyName string    `json:"company_name"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	Instances   int       `json:"instances"`
	Version     string    `json:"version"`
	CPUUsage    float64   `json:"cpu_usage"`
	MemoryUsage float64   `json:"memory_usage"`
	LastUpdated time.Time `json:"last_updated"`
}

// DeploymentList represents a list of deployments with summary information.
type DeploymentList struct {
	Deployments []DeploymentListItem `json:"deployments"`
	Total       int                  `json:"total"`
	Summary     DeploymentSummary    `json:"summary"`
	Timestamp   time.Time            `json:"timestamp"`
}

// DeploymentSummary provides summary statistics for deployments.
type DeploymentSummary struct {
	TotalJobs      int `json:"total_jobs"`
	RunningJobs    int `json:"running_jobs"`
	FailedJobs     int `json:"failed_jobs"`
	TotalInstances int `json:"total_instances"`
}
