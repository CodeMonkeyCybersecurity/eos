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
		Agents []Agent `json:"items"`
		Total  int     `json:"total_items"`
	} `json:"data"`
	Message string `json:"message"`
}

// PackageMapping represents a package mapping for different distributions
type PackageMapping struct {
	Distribution string
	Major        int
	Arch         string
	Package      string
}