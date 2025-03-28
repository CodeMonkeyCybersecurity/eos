// pkg/config/docker.go
package config

type ComposeFile struct {
	Services map[string]Service     `yaml:"services"`
	Volumes  map[string]interface{} `yaml:"volumes,omitempty"`
	Networks map[string]interface{} `yaml:"networks,omitempty"`
}

type Service struct {
	Image         string            `yaml:"image"`
	ContainerName string            `yaml:"container_name"`
	Ports         []string          `yaml:"ports,omitempty"`       // Maps "ports" section
	Environment   map[string]string `yaml:"environment,omitempty"` // Maps "environment" section
	Volumes       []string          `yaml:"volumes,omitempty"`     // Maps "volumes" section
	DependsOn     []string          `yaml:"depends_on,omitempty"`  // Maps "depends_on" section
	Restart       string            `yaml:"restart,omitempty"`     // Maps "restart" section
	Networks      []string          `yaml:"networks,omitempty"`    // Maps "networks" section
}
