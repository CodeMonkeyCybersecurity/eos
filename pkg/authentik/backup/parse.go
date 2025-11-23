// pkg/authentik/backup/parse.go
package backup

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ParseBackupFile reads and parses a backup file, extracting metadata
func ParseBackupFile(path string) (BackupFileInfo, error) {
	info := BackupFileInfo{Path: path}

	// Get file stats
	stat, err := os.Stat(path)
	if err != nil {
		return info, err
	}
	info.Size = stat.Size()
	info.ModTime = stat.ModTime()

	// Read and parse backup file
	data, err := os.ReadFile(path)
	if err != nil {
		return info, err
	}

	// Parse as YAML
	var backup struct {
		Metadata struct {
			SourceURL        string `yaml:"source_url"`
			AuthentikVersion string `yaml:"authentik_version"`
		} `yaml:"metadata"`
		Providers        []interface{} `yaml:"providers"`
		Applications     []interface{} `yaml:"applications"`
		PropertyMappings []interface{} `yaml:"property_mappings"`
		Flows            []interface{} `yaml:"flows"`
		Stages           []interface{} `yaml:"stages"`
		Groups           []interface{} `yaml:"groups"`
		Policies         []interface{} `yaml:"policies"`
		Certificates     []interface{} `yaml:"certificates"`
		Blueprints       []interface{} `yaml:"blueprints"`
		Outposts         []interface{} `yaml:"outposts"`
		Tenants          []interface{} `yaml:"tenants"`
	}

	if err := yaml.Unmarshal(data, &backup); err != nil {
		return info, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Extract info
	info.SourceURL = backup.Metadata.SourceURL
	info.AuthentikVersion = backup.Metadata.AuthentikVersion
	info.Providers = len(backup.Providers)
	info.Applications = len(backup.Applications)
	info.PropertyMappings = len(backup.PropertyMappings)
	info.Flows = len(backup.Flows)
	info.Stages = len(backup.Stages)
	info.Groups = len(backup.Groups)
	info.Policies = len(backup.Policies)
	info.Certificates = len(backup.Certificates)
	info.Blueprints = len(backup.Blueprints)
	info.Outposts = len(backup.Outposts)
	info.Tenants = len(backup.Tenants)

	return info, nil
}
