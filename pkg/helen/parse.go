package helen

import "github.com/spf13/cobra"

// parseHelenFlags parses command line flags and returns a Helen configuration
func ParseHelenFlags(cmd *cobra.Command) (*Config, error) {
	// Start with default configuration
	config := DefaultConfig()

	// Parse flags
	if port, err := cmd.Flags().GetInt("port"); err == nil && port != 0 {
		config.Port = port
	}

	if namespace, err := cmd.Flags().GetString("namespace"); err == nil && namespace != "" {
		config.Namespace = namespace
	}

	if vaultAddr, err := cmd.Flags().GetString("vault-addr"); err == nil && vaultAddr != "" {
		config.VaultAddr = vaultAddr
	}

	if nomadAddr, err := cmd.Flags().GetString("nomad-addr"); err == nil && nomadAddr != "" {
		config.NomadAddr = nomadAddr
	}

	if workDir, err := cmd.Flags().GetString("work-dir"); err == nil && workDir != "" {
		config.WorkDir = workDir
	}

	if host, err := cmd.Flags().GetString("host"); err == nil && host != "" {
		config.Host = host
	}

	if htmlPath, err := cmd.Flags().GetString("html-path"); err == nil && htmlPath != "" {
		config.PublicHTMLPath = htmlPath
	}

	if projectName, err := cmd.Flags().GetString("project-name"); err == nil && projectName != "" {
		config.ProjectName = projectName
	}

	// Resource configuration
	if cpu, err := cmd.Flags().GetInt("cpu"); err == nil && cpu > 0 {
		config.Resources.Nginx.CPU = cpu
	}

	if memory, err := cmd.Flags().GetInt("memory"); err == nil && memory > 0 {
		config.Resources.Nginx.Memory = memory
	}

	return config, nil
}
