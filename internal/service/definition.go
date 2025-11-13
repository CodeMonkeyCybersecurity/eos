package service

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ServiceDefinition captures the declarative description for a managed service.
type ServiceDefinition struct {
	Name           string         `yaml:"name"`
	Version        string         `yaml:"version"`
	Dependencies   Dependencies   `yaml:"dependencies"`
	HealthCheck    HealthCheck    `yaml:"healthcheck"`
	Initialization Initialization `yaml:"initialization"`
	Variables      Variables      `yaml:"variables"`
	Metadata       Metadata       `yaml:"metadata"`
}

// Metadata stores optional informational fields for operators.
type Metadata struct {
	Description string            `yaml:"description"`
	Owners      []string          `yaml:"owners"`
	Tags        map[string]string `yaml:"tags"`
}

// Dependencies describes the runtime requirements for a service.
type Dependencies struct {
	Containers []string `yaml:"containers"`
	Commands   []string `yaml:"commands"`
	Services   []string `yaml:"services"`
}

// HealthCheck defines the health validation strategy before and during init.
type HealthCheck struct {
	Type     string `yaml:"type"`
	URL      string `yaml:"url"`
	Timeout  string `yaml:"timeout"`
	Retries  int    `yaml:"retries"`
	Interval string `yaml:"interval"`
	Command  string `yaml:"command"`
}

// Initialization holds the ordered set of steps required to bring a service up.
type Initialization struct {
	Steps []InitStep `yaml:"steps"`
}

// InitStep captures a single initialization step.
type InitStep struct {
	Name            string            `yaml:"name"`
	Type            string            `yaml:"type"`
	Requires        []string          `yaml:"requires"`
	Retries         *RetryPolicy      `yaml:"retries"`
	IdempotentCheck *IdempotentCheck  `yaml:"idempotent_check"`
	API             *APIStep          `yaml:"api"`
	Then            *APIStep          `yaml:"then"`
	Query           string            `yaml:"query"`
	Database        string            `yaml:"database"`
	User            string            `yaml:"user"`
	Container       string            `yaml:"container"`
	Path            string            `yaml:"path"`
	Data            map[string]string `yaml:"data"`
	File            string            `yaml:"file"`
	Variables       map[string]string `yaml:"variables"`
	Containers      []string          `yaml:"containers"`
	Vault           *VaultWriteStep   `yaml:"vault_write"`
	Env             *EnvUpdateStep    `yaml:"env_update"`
	Docker          *DockerStep       `yaml:"docker_restart"`
	Outputs         map[string]string `yaml:"outputs"`
}

// RetryPolicy customises retry behaviour per step.
type RetryPolicy struct {
	MaxAttempts   int     `yaml:"max_attempts"`
	InitialDelay  string  `yaml:"initial_delay"`
	MaxDelay      string  `yaml:"max_delay"`
	BackoffFactor float64 `yaml:"backoff_factor"`
}

// IdempotentCheck specifies how to determine whether a step already completed.
type IdempotentCheck struct {
	Type      string `yaml:"type"`
	Query     string `yaml:"query"`
	Container string `yaml:"container"`
	User      string `yaml:"user"`
	Database  string `yaml:"database"`
	Endpoint  string `yaml:"endpoint"`
	Expected  string `yaml:"expected"`
}

// APIStep describes an HTTP interaction.
type APIStep struct {
	Method          string            `yaml:"method"`
	URL             string            `yaml:"url"`
	Headers         map[string]string `yaml:"headers"`
	BodyTemplate    string            `yaml:"body_template"`
	BodyFromFile    string            `yaml:"body_from_file"`
	SuccessCodes    []int             `yaml:"success_codes"`
	IdempotentCodes []int             `yaml:"idempotent_codes"`
	Extract         map[string]string `yaml:"extract"`
	ExtractCookie   string            `yaml:"extract_cookie"`
}

// VaultWriteStep encapsulates secure secret storage actions.
type VaultWriteStep struct {
	Path string            `yaml:"path"`
	Data map[string]string `yaml:"data"`
}

// EnvUpdateStep updates environment configuration files.
type EnvUpdateStep struct {
	File      string            `yaml:"file"`
	Variables map[string]string `yaml:"variables"`
}

// DockerStep controls docker operations post-initialisation.
type DockerStep struct {
	Containers []string `yaml:"containers"`
}

// Variables enumerates configuration inputs required by the definition.
type Variables struct {
	Required []string          `yaml:"required"`
	Optional map[string]string `yaml:"optional"`
}

// LoadDefinition resolves and loads a service definition by name.
func LoadDefinition(name string) (*ServiceDefinition, error) {
	if name == "" {
		return nil, fmt.Errorf("service name is required")
	}

	searchPaths := definitionSearchPaths()
	filename := fmt.Sprintf("%s.yaml", sanitizeName(name))

	var matchedPath string
	for _, base := range searchPaths {
		if base == "" {
			continue
		}

		path := filepath.Join(base, filename)
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("stat definition in %s: %w", path, err)
		}

		if info.IsDir() {
			continue
		}

		matchedPath = path
		break
	}

	if matchedPath == "" {
		return nil, fmt.Errorf("service definition %q not found in paths %v", name, searchPaths)
	}

	raw, err := os.ReadFile(matchedPath)
	if err != nil {
		return nil, fmt.Errorf("read definition %s: %w", matchedPath, err)
	}

	var def ServiceDefinition
	if err := yaml.Unmarshal(raw, &def); err != nil {
		return nil, fmt.Errorf("parse definition %s: %w", matchedPath, err)
	}

	if err := def.Validate(); err != nil {
		return nil, fmt.Errorf("invalid definition %s: %w", matchedPath, err)
	}

	return &def, nil
}

// Validate performs basic sanity checks on the definition.
func (d *ServiceDefinition) Validate() error {
	if d.Name == "" {
		return fmt.Errorf("name is required")
	}

	if len(d.Initialization.Steps) == 0 {
		return fmt.Errorf("initialization steps are required")
	}

	seen := make(map[string]struct{}, len(d.Initialization.Steps))
	for idx, step := range d.Initialization.Steps {
		if step.Name == "" {
			return fmt.Errorf("step %d is missing a name", idx+1)
		}

		if _, exists := seen[step.Name]; exists {
			return fmt.Errorf("step name %q is duplicated", step.Name)
		}
		seen[step.Name] = struct{}{}

		if step.Type == "" {
			return fmt.Errorf("step %q is missing required field 'type'", step.Name)
		}
	}

	return nil
}

// definitionSearchPaths returns candidate locations for service definitions.
func definitionSearchPaths() []string {
	var paths []string

	if env := os.Getenv("EOS_SERVICE_DEFINITIONS"); env != "" {
		for _, part := range strings.Split(env, string(os.PathListSeparator)) {
			part = strings.TrimSpace(part)
			if part != "" {
				paths = append(paths, part)
			}
		}
	}

	// Local repository checkout
	paths = append(paths, "services")

	// User-scoped configuration
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths,
			filepath.Join(home, ".config", "eos", "services"),
			filepath.Join(home, ".eos", "services"),
		)
	}

	// System-wide default
	paths = append(paths, "/opt/eos/services")

	unique := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		clean := filepath.Clean(p)
		if clean == "." || clean == "/" {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		unique = append(unique, clean)
	}
	return unique
}

// ListDefinitions returns the list of discoverable service definition names.
func ListDefinitions() ([]string, error) {
	searchPaths := definitionSearchPaths()
	seen := make(map[string]struct{})
	var results []string

	for _, base := range searchPaths {
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// Skip directories we cannot read rather than failing completely.
				return nil
			}

			if d.IsDir() {
				return nil
			}

			if filepath.Ext(path) != ".yaml" {
				return nil
			}

			name := strings.TrimSuffix(filepath.Base(path), ".yaml")
			if name == "" {
				return nil
			}

			if _, ok := seen[name]; ok {
				return nil
			}
			seen[name] = struct{}{}
			results = append(results, name)
			return nil
		})

		if err != nil {
			continue
		}
	}

	return results, nil
}

func sanitizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
