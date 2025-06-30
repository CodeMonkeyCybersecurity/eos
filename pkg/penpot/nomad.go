package penpot

import (
	"fmt"
	"time"

	"github.com/hashicorp/nomad/api"
)

// createNomadJobSpec creates the complete Nomad job specification for Penpot
func (m *Manager) createNomadJobSpec() (*api.Job, error) {
	job := &api.Job{
		ID:          stringPtr("penpot"),
		Name:        stringPtr("penpot"),
		Namespace:   stringPtr(m.config.Namespace),
		Type:        stringPtr("service"),
		Datacenters: m.config.Datacenters,
		TaskGroups: []*api.TaskGroup{
			{
				Name:  stringPtr("penpot-stack"),
				Count: intPtr(1),
				Networks: []*api.NetworkResource{
					{
						Mode: "bridge",
						DynamicPorts: []api.Port{
							{Label: "frontend", To: 80},
							{Label: "backend", To: 6060},
							{Label: "postgres", To: 5432},
							{Label: "redis", To: 6379},
							{Label: "exporter", To: 6061},
						},
						ReservedPorts: []api.Port{
							{Label: "public", Value: m.config.Port, To: 80},
						},
					},
				},
				Services: []*api.Service{
					{
						Name:      "penpot-frontend",
						PortLabel: "public",
						Tags:      []string{"penpot", "frontend", "web"},
						Checks: []api.ServiceCheck{
							{
								Type:     "http",
								Path:     "/",
								Interval: 30 * time.Second,
								Timeout:  5 * time.Second,
								Header: map[string][]string{
									"User-Agent": {"Nomad Health Check"},
								},
							},
						},
					},
					{
						Name:      "penpot-backend",
						PortLabel: "backend",
						Tags:      []string{"penpot", "backend", "api"},
						Checks: []api.ServiceCheck{
							{
								Type:     "http",
								Path:     "/api/health",
								Interval: 30 * time.Second,
								Timeout:  5 * time.Second,
							},
						},
					},
				},
				Tasks: []*api.Task{
					m.createPostgresTask(),
					m.createRedisTask(),
					m.createPenpotBackendTask(),
					m.createPenpotFrontendTask(),
					m.createPenpotExporterTask(),
				},
			},
		},
	}

	return job, nil
}

// createPostgresTask creates the PostgreSQL database task
func (m *Manager) createPostgresTask() *api.Task {
	return &api.Task{
		Name:   "postgres",
		Driver: "docker",
		Config: map[string]interface{}{
			"image": "postgres:15",
			"ports": []string{"postgres"},
			"volumes": []string{
				"penpot-postgres:/var/lib/postgresql/data",
			},
		},
		Vault: &api.Vault{
			Policies: []string{"nomad-penpot"},
		},
		Templates: []*api.Template{
			{
				EmbeddedTmpl: stringPtr(`
{{ with secret "secret/data/postgres" }}
POSTGRES_USER={{ .Data.data.username }}
POSTGRES_PASSWORD={{ .Data.data.password }}
POSTGRES_DB={{ .Data.data.database }}
{{ end }}
POSTGRES_INITDB_ARGS=--encoding=UTF-8 --lc-collate=C --lc-ctype=C
`),
				DestPath: stringPtr("secrets/postgres.env"),
				Envvars:  boolPtr(true),
			},
		},
		Resources: &api.Resources{
			CPU:      intPtr(m.config.Resources.Database.CPU),
			MemoryMB: intPtr(m.config.Resources.Database.Memory),
		},
		RestartPolicy: &api.RestartPolicy{
			Attempts: intPtr(3),
			Delay:    durationPtr(15 * time.Second),
			Interval: durationPtr(5 * time.Minute),
			Mode:     stringPtr("fail"),
		},
		Services: []*api.Service{
			{
				Name:      "postgres",
				PortLabel: "postgres",
				Tags:      []string{"database", "postgres"},
				Checks: []api.ServiceCheck{
					{
						Type:     "script",
						Name:     "postgres-health",
						Command:  "pg_isready",
						Args:     []string{"-U", "penpot"},
						Interval: 30 * time.Second,
						Timeout:  5 * time.Second,
					},
				},
			},
		},
	}
}

// createRedisTask creates the Redis cache task
func (m *Manager) createRedisTask() *api.Task {
	return &api.Task{
		Name:   "redis",
		Driver: "docker",
		Config: map[string]interface{}{
			"image": "redis:7",
			"ports": []string{"redis"},
			"args": []string{
				"redis-server",
				"--save", "60", "1",
				"--loglevel", "warning",
			},
			"volumes": []string{
				"penpot-redis:/data",
			},
		},
		Resources: &api.Resources{
			CPU:      intPtr(m.config.Resources.Redis.CPU),
			MemoryMB: intPtr(m.config.Resources.Redis.Memory),
		},
		RestartPolicy: &api.RestartPolicy{
			Attempts: intPtr(3),
			Delay:    durationPtr(15 * time.Second),
			Interval: durationPtr(5 * time.Minute),
			Mode:     stringPtr("fail"),
		},
		Services: []*api.Service{
			{
				Name:      "redis",
				PortLabel: "redis",
				Tags:      []string{"cache", "redis"},
				Checks: []api.ServiceCheck{
					{
						Type:     "script",
						Name:     "redis-health",
						Command:  "redis-cli",
						Args:     []string{"ping"},
						Interval: 30 * time.Second,
						Timeout:  5 * time.Second,
					},
				},
			},
		},
	}
}

// createPenpotBackendTask creates the Penpot backend task
func (m *Manager) createPenpotBackendTask() *api.Task {
	return &api.Task{
		Name:   "backend",
		Driver: "docker",
		Config: map[string]interface{}{
			"image": "penpotapp/backend:latest",
			"ports": []string{"backend"},
			"volumes": []string{
				"penpot-assets:/opt/penpot/assets",
			},
		},
		Vault: &api.Vault{
			Policies: []string{"nomad-penpot"},
		},
		Templates: []*api.Template{
			{
				EmbeddedTmpl: stringPtr(`
{{ with secret "secret/data/penpot" }}
PENPOT_DATABASE_URI={{ .Data.data.database_uri }}
PENPOT_REDIS_URI={{ .Data.data.redis_uri }}
PENPOT_SECRET_KEY={{ .Data.data.secret_key }}
PENPOT_PUBLIC_URI={{ .Data.data.public_uri }}
{{ end }}
# Feature flags
PENPOT_FLAGS=` + m.buildFeatureFlags() + `
# Storage configuration
PENPOT_ASSETS_STORAGE_BACKEND=fs
PENPOT_STORAGE_ASSETS_FS_DIRECTORY=/opt/penpot/assets
# Email configuration (disabled for now)
PENPOT_EMAIL_ENABLED=false
# Telemetry
PENPOT_TELEMETRY_ENABLED=false
# Performance settings
PENPOT_HTTP_SERVER_PORT=6060
PENPOT_HTTP_SERVER_HOST=0.0.0.0
`),
				DestPath: stringPtr("secrets/backend.env"),
				Envvars:  boolPtr(true),
			},
		},
		Resources: &api.Resources{
			CPU:      intPtr(m.config.Resources.Backend.CPU),
			MemoryMB: intPtr(m.config.Resources.Backend.Memory),
		},
		RestartPolicy: &api.RestartPolicy{
			Attempts: intPtr(3),
			Delay:    durationPtr(30 * time.Second),
			Interval: durationPtr(10 * time.Minute),
			Mode:     stringPtr("fail"),
		},
		Services: []*api.Service{
			{
				Name:      "penpot-backend",
				PortLabel: "backend",
				Tags:      []string{"backend", "api"},
				Checks: []api.ServiceCheck{
					{
						Type:     "http",
						Path:     "/api/health",
						Interval: 30 * time.Second,
						Timeout:  10 * time.Second,
					},
				},
			},
		},
	}
}

// createPenpotFrontendTask creates the Penpot frontend task
func (m *Manager) createPenpotFrontendTask() *api.Task {
	return &api.Task{
		Name:   "frontend",
		Driver: "docker",
		Config: map[string]interface{}{
			"image": "penpotapp/frontend:latest",
			"ports": []string{"frontend"},
		},
		Env: map[string]string{
			"PENPOT_BACKEND_URI":  "http://localhost:6060",
			"PENPOT_EXPORTER_URI": "http://localhost:6061",
			"PENPOT_FLAGS":        m.buildFeatureFlags(),
		},
		Resources: &api.Resources{
			CPU:      intPtr(m.config.Resources.Frontend.CPU),
			MemoryMB: intPtr(m.config.Resources.Frontend.Memory),
		},
		RestartPolicy: &api.RestartPolicy{
			Attempts: intPtr(3),
			Delay:    durationPtr(15 * time.Second),
			Interval: durationPtr(5 * time.Minute),
			Mode:     stringPtr("fail"),
		},
		Services: []*api.Service{
			{
				Name:      "penpot-frontend",
				PortLabel: "frontend",
				Tags:      []string{"frontend", "web"},
				Checks: []api.ServiceCheck{
					{
						Type:     "http",
						Path:     "/",
						Interval: 30 * time.Second,
						Timeout:  5 * time.Second,
					},
				},
			},
		},
	}
}

// createPenpotExporterTask creates the Penpot exporter task
func (m *Manager) createPenpotExporterTask() *api.Task {
	return &api.Task{
		Name:   "exporter",
		Driver: "docker",
		Config: map[string]interface{}{
			"image": "penpotapp/exporter:latest",
			"ports": []string{"exporter"},
		},
		Env: map[string]string{
			"PENPOT_PUBLIC_URI":       fmt.Sprintf("http://localhost:%d", m.config.Port),
			"PENPOT_EXPORTER_CONCURRENCY": "2",
		},
		Resources: &api.Resources{
			CPU:      intPtr(m.config.Resources.Exporter.CPU),
			MemoryMB: intPtr(m.config.Resources.Exporter.Memory),
		},
		RestartPolicy: &api.RestartPolicy{
			Attempts: intPtr(3),
			Delay:    durationPtr(15 * time.Second),
			Interval: durationPtr(5 * time.Minute),
			Mode:     stringPtr("fail"),
		},
		Services: []*api.Service{
			{
				Name:      "penpot-exporter",
				PortLabel: "exporter",
				Tags:      []string{"exporter", "pdf"},
				Checks: []api.ServiceCheck{
					{
						Type:     "http",
						Path:     "/health",
						Interval: 30 * time.Second,
						Timeout:  5 * time.Second,
					},
				},
			},
		},
	}
}

// buildFeatureFlags builds the feature flags string based on configuration
func (m *Manager) buildFeatureFlags() string {
	var flags []string
	
	if m.config.EnableRegistration {
		flags = append(flags, "enable-registration")
	}
	
	if m.config.EnableLogin {
		flags = append(flags, "enable-login")
	}
	
	if m.config.DisableEmailVerif {
		flags = append(flags, "disable-email-verification")
	}
	
	// Join flags with spaces
	result := ""
	for i, flag := range flags {
		if i > 0 {
			result += " "
		}
		result += flag
	}
	
	return result
}

// Helper pointer functions for Nomad API
func stringPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}

func boolPtr(b bool) *bool {
	return &b
}

func durationPtr(d time.Duration) *time.Duration {
	return &d
}