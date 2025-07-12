package hecate

// TerraformConfig represents configuration for Hecate Terraform generation
// Migrated from cmd/create/hecate_terraform.go HecateConfig
type TerraformConfig struct {
	UseHetzner bool   `json:"use_hetzner"`
	DockerHost string `json:"docker_host"`
	ServerName string `json:"server_name"`
	ServerType string `json:"server_type"`
	Location   string `json:"location"`
	Domain     string `json:"domain"`
}
