package agents

// OSInfo represents operating system information
type OSInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}

// Agent represents a Delphi/Wazuh agent
type Agent struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	OS      OSInfo `json:"os"`
}

// AgentsResponse represents the API response containing agents
type AgentsResponse struct {
	Data struct {
		AffectedItems []Agent `json:"affected_items"`
		TotalItems    int     `json:"total_items"`
		TotalAffected int     `json:"total_affected_items"`
		FailedItems   int     `json:"failed_items"`
	} `json:"data"`
	Error   int    `json:"error"`
	Message string `json:"message"`
}

// PackageMapping represents a package mapping for different distributions
type PackageMapping struct {
	Distribution string
	MinVersion   int
	Arch         string
	Package      string
}
