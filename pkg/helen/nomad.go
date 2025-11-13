package helen

import (
	"fmt"
	"time"

	"github.com/hashicorp/nomad/api"
)

// createNomadJobSpec creates the complete Nomad job specification for Helen nginx
func (m *Manager) createNomadJobSpec() (*api.Job, error) {
	job := &api.Job{
		ID:          stringPtr("helen"),
		Name:        stringPtr("helen"),
		Namespace:   stringPtr(m.config.Namespace),
		Type:        stringPtr("service"),
		Datacenters: m.config.Datacenters,
		TaskGroups: []*api.TaskGroup{
			{
				Name:  stringPtr("helen-nginx"),
				Count: intPtr(1),
				Networks: []*api.NetworkResource{
					{
						Mode: "bridge",
						ReservedPorts: []api.Port{
							{Label: "http", Value: m.config.Port, To: 80},
						},
					},
				},
				Services: []*api.Service{
					{
						Name:      "helen-web",
						PortLabel: "http",
						Tags:      []string{"helen", "nginx", "web"},
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
				},
				Tasks: []*api.Task{
					m.createNginxTask(),
				},
			},
		},
		Meta: map[string]string{
			"deployment_time": time.Now().Format(time.RFC3339),
			"deployed_by":     "eos-helen-cli",
			"html_path":       m.config.PublicHTMLPath,
		},
	}

	return job, nil
}

// createNginxTask creates the nginx container task with security features
func (m *Manager) createNginxTask() *api.Task {
	return &api.Task{
		Name:   "nginx",
		Driver: "docker",
		Config: map[string]interface{}{
			"image": "nginx:alpine",
			"ports": []string{"http"},
			"volumes": []string{
				fmt.Sprintf("%s:/usr/share/nginx/html:ro", m.config.PublicHTMLPath),
			},
			// Security features from the original docker-compose
			"readonly_rootfs": true,
			"mount": []map[string]interface{}{
				{
					"type":   "tmpfs",
					"target": "/tmp",
					"tmpfs_options": map[string]interface{}{
						"size": 10485760, // 10MB
					},
				},
				{
					"type":   "tmpfs",
					"target": "/var/cache/nginx",
					"tmpfs_options": map[string]interface{}{
						"size": 52428800, // 50MB
					},
				},
				{
					"type":   "tmpfs",
					"target": "/var/run",
					"tmpfs_options": map[string]interface{}{
						"size": 5242880, // 5MB
					},
				},
			},
			"security_opt": []string{
				"no-new-privileges:true",
			},
		},
		Vault: &api.Vault{
			Policies: []string{"helen-policy"},
		},
		Templates: []*api.Template{
			{
				EmbeddedTmpl: stringPtr(`
{{ with secret "secret/data/helen/{{ env "NOMAD_NAMESPACE" }}" }}
# Helen deployment metadata
DEPLOYMENT_TIME={{ .Data.data.deployment_time }}
PROJECT_NAME={{ .Data.data.project_name }}
NAMESPACE={{ .Data.data.namespace }}
{{ end }}
# Nginx configuration
NGINX_WORKER_PROCESSES=1
NGINX_WORKER_CONNECTIONS=1024
`),
				DestPath: stringPtr("secrets/helen.env"),
				Envvars:  boolPtr(true),
			},
		},
		Resources: &api.Resources{
			CPU:      intPtr(m.config.Resources.Nginx.CPU),
			MemoryMB: intPtr(m.config.Resources.Nginx.Memory),
		},
		RestartPolicy: &api.RestartPolicy{
			Attempts: intPtr(3),
			Delay:    durationPtr(15 * time.Second),
			Interval: durationPtr(5 * time.Minute),
			Mode:     stringPtr("fail"),
		},
		Services: []*api.Service{
			{
				Name:      "helen-nginx",
				PortLabel: "http",
				Tags:      []string{"nginx", "web", "static"},
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
		Env: map[string]string{
			"NGINX_WORKER_PROCESSES":   "1",
			"NGINX_WORKER_CONNECTIONS": "1024",
		},
		// Set user to nginx (non-root)
		User: "nginx",
		// Constraints to ensure proper node placement
		Constraints: []*api.Constraint{
			{
				LTarget: "${driver.docker}",
				RTarget: "1",
				Operand: "=",
			},
		},
	}
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
