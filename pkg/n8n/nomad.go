package n8n

import (
	"fmt"
	"time"

	"github.com/hashicorp/nomad/api"
)

// createPostgresJob creates a Nomad job for PostgreSQL
func (m *Manager) createPostgresJob() *api.Job {
	job := &api.Job{
		ID:          stringPtr("n8n-postgres"),
		Name:        stringPtr("n8n-postgres"),
		Type:        stringPtr("service"),
		Datacenters: []string{m.config.Datacenter},
		TaskGroups: []*api.TaskGroup{
			{
				Name:  stringPtr("postgres"),
				Count: intPtr(1),
				Networks: []*api.NetworkResource{
					{
						Mode: "bridge",
						ReservedPorts: []api.Port{
							{
								Label: "postgres",
								Value: m.config.PostgresPort,
								To:    5432,
							},
						},
					},
				},
				Services: []*api.Service{
					{
						Name:      "n8n-postgres",
						PortLabel: "postgres",
						Checks: []api.ServiceCheck{
							{
								Type:     "tcp",
								Interval: 10 * time.Second,
								Timeout:  3 * time.Second,
							},
						},
					},
				},
				Tasks: []*api.Task{
					{
						Name:   "postgres",
						Driver: "docker",
						Config: map[string]interface{}{
							"image": "postgres:15",
							"ports": []string{"postgres"},
							"volumes": []string{
								"n8n_postgres_data:/var/lib/postgresql/data",
							},
						},
						Env: map[string]string{
							"POSTGRES_DB":       m.config.PostgresDB,
							"POSTGRES_USER":     m.config.PostgresUser,
							"POSTGRES_PASSWORD": m.config.PostgresPassword,
						},
						Resources: &api.Resources{
							CPU:      intPtr(500),
							MemoryMB: intPtr(512),
						},
					},
				},
			},
		},
	}

	return job
}

// createRedisJob creates a Nomad job for Redis
func (m *Manager) createRedisJob() *api.Job {
	job := &api.Job{
		ID:          stringPtr("n8n-redis"),
		Name:        stringPtr("n8n-redis"),
		Type:        stringPtr("service"),
		Datacenters: []string{m.config.Datacenter},
		TaskGroups: []*api.TaskGroup{
			{
				Name:  stringPtr("redis"),
				Count: intPtr(1),
				Networks: []*api.NetworkResource{
					{
						Mode: "bridge",
						ReservedPorts: []api.Port{
							{
								Label: "redis",
								Value: m.config.RedisPort,
								To:    6379,
							},
						},
					},
				},
				Services: []*api.Service{
					{
						Name:      "n8n-redis",
						PortLabel: "redis",
						Checks: []api.ServiceCheck{
							{
								Type:     "tcp",
								Interval: 10 * time.Second,
								Timeout:  3 * time.Second,
							},
						},
					},
				},
				Tasks: []*api.Task{
					{
						Name:   "redis",
						Driver: "docker",
						Config: map[string]interface{}{
							"image": "redis:7-alpine",
							"ports": []string{"redis"},
							"args":  []string{"redis-server", "--appendonly", "yes"},
							"volumes": []string{
								"n8n_redis_data:/data",
							},
						},
						Resources: &api.Resources{
							CPU:      intPtr(200),
							MemoryMB: intPtr(256),
						},
					},
				},
			},
		},
	}

	return job
}

// createN8nJob creates a Nomad job for n8n main service and workers
func (m *Manager) createN8nJob() *api.Job {
	job := &api.Job{
		ID:          stringPtr("n8n"),
		Name:        stringPtr("n8n"),
		Type:        stringPtr("service"),
		Datacenters: []string{m.config.Datacenter},
		TaskGroups: []*api.TaskGroup{
			{
				Name:  stringPtr("n8n-main"),
				Count: intPtr(1),
				Networks: []*api.NetworkResource{
					{
						Mode: "bridge",
						ReservedPorts: []api.Port{
							{
								Label: "n8n",
								Value: m.config.Port,
								To:    5678,
							},
						},
					},
				},
				Services: []*api.Service{
					{
						Name:      "n8n",
						PortLabel: "n8n",
						Checks: []api.ServiceCheck{
							{
								Type:     "http",
								Path:     "/healthz",
								Interval: 30 * time.Second,
								Timeout:  10 * time.Second,
							},
						},
					},
				},
				Tasks: []*api.Task{
					{
						Name:   "n8n-main",
						Driver: "docker",
						Config: map[string]interface{}{
							"image": "n8nio/n8n:latest",
							"ports": []string{"n8n"},
						},
						Env: m.getN8nEnvironment(),
						Resources: &api.Resources{
							CPU:      intPtr(m.config.CPU),
							MemoryMB: intPtr(m.config.Memory),
						},
					},
				},
			},
		},
	}

	// Add worker task groups if workers > 1
	if m.config.Workers > 1 {
		workerTaskGroup := &api.TaskGroup{
			Name:  stringPtr("n8n-workers"),
			Count: intPtr(m.config.Workers - 1), // Main service counts as 1 worker
			Tasks: []*api.Task{
				{
					Name:   "n8n-worker",
					Driver: "docker",
					Config: map[string]interface{}{
						"image":   "n8nio/n8n:latest",
						"command": "worker",
					},
					Env: m.getN8nWorkerEnvironment(),
					Resources: &api.Resources{
						CPU:      intPtr(m.config.CPU / 2), // Workers use less CPU
						MemoryMB: intPtr(m.config.Memory / 2),
					},
				},
			},
		}
		job.TaskGroups = append(job.TaskGroups, workerTaskGroup)
	}

	return job
}

// createNginxJob creates a Nomad job for nginx reverse proxy
func (m *Manager) createNginxJob() *api.Job {
	job := &api.Job{
		ID:          stringPtr("n8n-nginx"),
		Name:        stringPtr("n8n-nginx"),
		Type:        stringPtr("service"),
		Datacenters: []string{m.config.Datacenter},
		TaskGroups: []*api.TaskGroup{
			{
				Name:  stringPtr("nginx"),
				Count: intPtr(1),
				Networks: []*api.NetworkResource{
					{
						Mode: "bridge",
						ReservedPorts: []api.Port{
							{
								Label: "nginx",
								Value: 80,
								To:    80,
							},
							{
								Label: "nginx-ssl",
								Value: 443,
								To:    443,
							},
						},
					},
				},
				Services: []*api.Service{
					{
						Name:      "n8n-nginx",
						PortLabel: "nginx",
						Checks: []api.ServiceCheck{
							{
								Type:     "http",
								Path:     "/health",
								Interval: 30 * time.Second,
								Timeout:  10 * time.Second,
							},
						},
					},
				},
				Tasks: []*api.Task{
					{
						Name:   "nginx",
						Driver: "docker",
						Config: map[string]interface{}{
							"image": "nginx:alpine",
							"ports": []string{"nginx", "nginx-ssl"},
						},
						Templates: []*api.Template{
							{
								DestPath:   stringPtr("/etc/nginx/nginx.conf"),
								EmbeddedTmpl: stringPtr(m.getNginxConfig()),
							},
						},
						Resources: &api.Resources{
							CPU:      intPtr(200),
							MemoryMB: intPtr(128),
						},
					},
				},
			},
		},
	}

	return job
}
func (m *Manager) getN8nEnvironment() map[string]string {
	return map[string]string{
		// Database
		"DB_TYPE":                    "postgresdb",
		"DB_POSTGRESDB_HOST":         m.config.PostgresHost,
		"DB_POSTGRESDB_PORT":         fmt.Sprintf("%d", m.config.PostgresPort),
		"DB_POSTGRESDB_DATABASE":     m.config.PostgresDB,
		"DB_POSTGRESDB_USER":         m.config.PostgresUser,
		"DB_POSTGRESDB_PASSWORD":     m.config.PostgresPassword,

		// n8n Configuration
		"N8N_BASIC_AUTH_ACTIVE":      "true",
		"N8N_BASIC_AUTH_USER":        m.config.BasicAuthUser,
		"N8N_BASIC_AUTH_PASSWORD":    m.config.BasicAuthPassword,
		"N8N_HOST":                   m.config.Domain,
		"N8N_PORT":                   fmt.Sprintf("%d", m.config.Port),
		"N8N_PROTOCOL":               m.config.Protocol,
		"WEBHOOK_URL":                fmt.Sprintf("%s://%s/", m.config.Protocol, m.config.Domain),

		// Security
		"N8N_JWT_AUTH_HEADER":              "authorization",
		"N8N_JWT_AUTH_HEADER_VALUE_PREFIX": "Bearer",
		"N8N_ENCRYPTION_KEY":               m.config.EncryptionKey,

		// Scaling & Performance
		"QUEUE_BULL_REDIS_HOST":    m.config.RedisHost,
		"QUEUE_BULL_REDIS_PORT":    fmt.Sprintf("%d", m.config.RedisPort),
		"EXECUTIONS_MODE":          "queue",
		"QUEUE_HEALTH_CHECK_ACTIVE": "true",

		// Logging
		"N8N_LOG_LEVEL":     "info",
		"N8N_LOG_OUTPUT":    "console,file",
		"N8N_LOG_FILE_LOCATION": "/home/node/.n8n/logs/n8n.log",

		// User Management
		"N8N_USER_MANAGEMENT_DISABLED": fmt.Sprintf("%t", !m.config.EnableUserManagement),
		"N8N_PUBLIC_API_DISABLED":      fmt.Sprintf("%t", !m.config.EnablePublicAPI),

		// Security Headers
		"N8N_SECURE_COOKIE": fmt.Sprintf("%t", m.config.SecureCookies),
		"N8N_COOKIES_SECURE": fmt.Sprintf("%t", m.config.SecureCookies),

		// Timezone
		"GENERIC_TIMEZONE": m.config.Timezone,
		"TZ":               m.config.Timezone,
	}
}

// getN8nWorkerEnvironment returns environment variables for n8n workers
func (m *Manager) getN8nWorkerEnvironment() map[string]string {
	env := map[string]string{
		// Database (same as main n8n)
		"DB_TYPE":                "postgresdb",
		"DB_POSTGRESDB_HOST":     m.config.PostgresHost,
		"DB_POSTGRESDB_PORT":     fmt.Sprintf("%d", m.config.PostgresPort),
		"DB_POSTGRESDB_DATABASE": m.config.PostgresDB,
		"DB_POSTGRESDB_USER":     m.config.PostgresUser,
		"DB_POSTGRESDB_PASSWORD": m.config.PostgresPassword,

		// Queue Configuration
		"QUEUE_BULL_REDIS_HOST": m.config.RedisHost,
		"QUEUE_BULL_REDIS_PORT": fmt.Sprintf("%d", m.config.RedisPort),
		"EXECUTIONS_MODE":       "queue",

		// Security
		"N8N_ENCRYPTION_KEY": m.config.EncryptionKey,

		// Logging
		"N8N_LOG_LEVEL":         "info",
		"N8N_LOG_OUTPUT":        "console,file",
		"N8N_LOG_FILE_LOCATION": "/home/node/.n8n/logs/n8n-worker.log",

		// Timezone
		"GENERIC_TIMEZONE": m.config.Timezone,
		"TZ":               m.config.Timezone,
	}

	// Add email configuration if provided
	if m.config.SMTPHost != "" {
		env["N8N_EMAIL_MODE"] = "smtp"
		env["N8N_SMTP_HOST"] = m.config.SMTPHost
		env["N8N_SMTP_PORT"] = fmt.Sprintf("%d", m.config.SMTPPort)
		env["N8N_SMTP_USER"] = m.config.SMTPUser
		env["N8N_SMTP_PASS"] = m.config.SMTPPass
		env["N8N_SMTP_SENDER"] = m.config.SMTPSender
	}

	return env
}

// getNginxConfig returns nginx configuration template
func (m *Manager) getNginxConfig() string {
	return fmt.Sprintf(`
events {
    worker_connections 1024;
}

http {
    upstream n8n_backend {
        server {{ range service "n8n" }}{{ .Address }}:{{ .Port }};{{ end }}
    }

    server {
        listen 80;
        server_name %s;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name %s;

        ssl_certificate /etc/ssl/certs/cert.pem;
        ssl_certificate_key /etc/ssl/certs/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;

        # Security headers
        add_header Strict-Transport-Security "max-age=63072000" always;
        add_header X-Frame-Options DENY always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;

        location / {
            proxy_pass http://n8n_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # WebSocket support
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            
            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }
    }
}
`, m.config.Domain, m.config.Domain)
}

// Helper functions for pointer conversion
func stringPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}
