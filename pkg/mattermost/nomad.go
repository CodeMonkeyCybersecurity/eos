package mattermost

import (
	"fmt"
	"time"

	"github.com/hashicorp/nomad/api"
)

// createPostgresJob creates a Nomad job for PostgreSQL database
func (m *Manager) createPostgresJob() *api.Job {
	job := &api.Job{
		ID:          stringPtr("mattermost-postgres"),
		Name:        stringPtr("mattermost-postgres"),
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
						Name:      "mattermost-postgres",
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
								"mattermost_postgres_data:/var/lib/postgresql/data",
							},
						},
						Env: map[string]string{
							"POSTGRES_DB":       m.config.PostgresDB,
							"POSTGRES_USER":     m.config.PostgresUser,
							"POSTGRES_PASSWORD": m.config.PostgresPassword,
							"POSTGRES_INITDB_ARGS": "--encoding=UTF8 --locale=en_US.UTF-8",
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

// createMattermostJob creates a Nomad job for Mattermost application
func (m *Manager) createMattermostJob() *api.Job {
	job := &api.Job{
		ID:          stringPtr("mattermost"),
		Name:        stringPtr("mattermost"),
		Type:        stringPtr("service"),
		Datacenters: []string{m.config.Datacenter},
		TaskGroups: []*api.TaskGroup{
			{
				Name:  stringPtr("mattermost"),
				Count: intPtr(m.config.Replicas),
				Networks: []*api.NetworkResource{
					{
						Mode: "bridge",
						ReservedPorts: []api.Port{
							{
								Label: "mattermost",
								Value: m.config.Port,
								To:    8065,
							},
						},
					},
				},
				Services: []*api.Service{
					{
						Name:      "mattermost",
						PortLabel: "mattermost",
						Checks: []api.ServiceCheck{
							{
								Type:     "http",
								Path:     "/api/v4/system/ping",
								Interval: 30 * time.Second,
								Timeout:  10 * time.Second,
							},
						},
					},
				},
				Tasks: []*api.Task{
					{
						Name:   "mattermost",
						Driver: "docker",
						Config: map[string]interface{}{
							"image": "mattermost/mattermost-team-edition:latest",
							"ports": []string{"mattermost"},
							"volumes": []string{
								"mattermost_config:/mattermost/config",
								"mattermost_data:/mattermost/data",
								"mattermost_logs:/mattermost/logs",
								"mattermost_plugins:/mattermost/plugins",
								"mattermost_client_plugins:/mattermost/client/plugins",
								"mattermost_bleve:/mattermost/bleve-indexes",
							},
						},
						Env: m.getMattermostEnvironment(),
						Resources: &api.Resources{
							CPU:      intPtr(m.config.CPU),
							MemoryMB: intPtr(m.config.Memory),
						},
					},
				},
			},
		},
	}

	return job
}

// createNginxJob creates a Nomad job for local nginx reverse proxy
// This serves as Layer 2 (Backend) in the Hecate two-layer architecture
func (m *Manager) createNginxJob() *api.Job {
	job := &api.Job{
		ID:          stringPtr("mattermost-nginx"),
		Name:        stringPtr("mattermost-nginx"),
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
						},
					},
				},
				Services: []*api.Service{
					{
						Name:      "mattermost-nginx",
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
							"ports": []string{"nginx"},
						},
						Templates: []*api.Template{
							{
								DestPath:     stringPtr("/etc/nginx/nginx.conf"),
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

// getMattermostEnvironment returns environment variables for Mattermost
func (m *Manager) getMattermostEnvironment() map[string]string {
	return map[string]string{
		// Database Configuration
		"MM_SQLSETTINGS_DRIVERNAME":     "postgres",
		"MM_SQLSETTINGS_DATASOURCE":     fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable&connect_timeout=10", 
			m.config.PostgresUser, m.config.PostgresPassword, m.config.PostgresHost, m.config.PostgresPort, m.config.PostgresDB),

		// Server Configuration
		"MM_SERVICESETTINGS_SITEURL":                fmt.Sprintf("%s://%s", m.config.Protocol, m.config.Domain),
		"MM_SERVICESETTINGS_LISTENADDRESS":          ":8065",
		"MM_SERVICESETTINGS_CONNECTIONSECURITY":     "",
		"MM_SERVICESETTINGS_TLSCERTFILE":            "",
		"MM_SERVICESETTINGS_TLSKEYFILE":             "",
		"MM_SERVICESETTINGS_USELETSENCRPYT":         "false",
		"MM_SERVICESETTINGS_FORWARD80TO443":         "false",
		"MM_SERVICESETTINGS_READTIMEOUT":            "300",
		"MM_SERVICESETTINGS_WRITETIMEOUT":           "300",
		"MM_SERVICESETTINGS_MAXLOGINATTEMPTSPERIP":  "10",
		"MM_SERVICESETTINGS_MAXLOGINATTEMPTS":       "10",

		// File Storage
		"MM_FILESETTINGS_DRIVERNAME":                "local",
		"MM_FILESETTINGS_DIRECTORY":                 "/mattermost/data/",
		"MM_FILESETTINGS_ENABLEPUBLICLINK":          "false",
		"MM_FILESETTINGS_MAXFILESIZE":               "52428800",

		// Email Configuration
		"MM_EMAILSETTINGS_ENABLESIGNUPWITHEMAIL":    "true",
		"MM_EMAILSETTINGS_ENABLESIGNINWITHEMAIL":    "true",
		"MM_EMAILSETTINGS_ENABLESIGNINWITHUSERNAME": "true",
		"MM_EMAILSETTINGS_SENDEMAILNOTIFICATIONS":   "false",
		"MM_EMAILSETTINGS_REQUIREEMAILVERIFICATION": "false",

		// Security
		"MM_PASSWORDSETTINGS_MINIMUMLENGTH":         "5",
		"MM_PASSWORDSETTINGS_LOWERCASE":             "false",
		"MM_PASSWORDSETTINGS_NUMBER":                "false",
		"MM_PASSWORDSETTINGS_UPPERCASE":             "false",
		"MM_PASSWORDSETTINGS_SYMBOL":                "false",

		// Team Settings
		"MM_TEAMSETTINGS_SITENAME":                  "Mattermost",
		"MM_TEAMSETTINGS_MAXUSERSPERTEAM":           "50",
		"MM_TEAMSETTINGS_ENABLETEAMCREATION":        "true",
		"MM_TEAMSETTINGS_ENABLEUSERCREATION":        "true",
		"MM_TEAMSETTINGS_ENABLEOPENCREATION":        "false",
		"MM_TEAMSETTINGS_RESTRICTCREATIONTODOMAINS": "",

		// Logging
		"MM_LOGSETTINGS_ENABLECONSOLE":              "true",
		"MM_LOGSETTINGS_CONSOLELEVEL":               "INFO",
		"MM_LOGSETTINGS_ENABLEFILE":                 "true",
		"MM_LOGSETTINGS_FILELEVEL":                  "INFO",
		"MM_LOGSETTINGS_FILEFORMAT":                 "",
		"MM_LOGSETTINGS_FILELOCATION":               "/mattermost/logs/mattermost.log",

		// Plugin Settings
		"MM_PLUGINSETTINGS_ENABLE":                  "true",
		"MM_PLUGINSETTINGS_ENABLEUPLOADS":           "true",
		"MM_PLUGINSETTINGS_DIRECTORY":               "/mattermost/plugins",
		"MM_PLUGINSETTINGS_CLIENTDIRECTORY":         "/mattermost/client/plugins",

		// Support Settings
		"MM_SUPPORTSETTINGS_SUPPORTEMAIL":           m.config.SupportEmail,
		"MM_SUPPORTSETTINGS_ABOUTLINK":              "https://about.mattermost.com/",
		"MM_SUPPORTSETTINGS_HELPLINK":               "https://about.mattermost.com/help/",
		"MM_SUPPORTSETTINGS_REPORTAPROBLEMLINK":     "https://about.mattermost.com/report-problem/",

		// Security Keys
		"MM_SERVICESETTINGS_PUBLICLINKKEY":          m.config.FilePublicKey,
		"MM_SERVICESETTINGS_PRIVATELINKKEY":         m.config.FilePrivateKey,
		"MM_EMAILSETTINGS_INVITESALT":               m.config.InviteSalt,

		// Timezone
		"TZ": m.config.Timezone,
	}
}

// getNginxConfig returns nginx configuration template for Mattermost
func (m *Manager) getNginxConfig() string {
	return fmt.Sprintf(`
events {
    worker_connections 1024;
}

http {
    upstream mattermost_backend {
        server {{ range service "mattermost" }}{{ .Address }}:{{ .Port }};{{ end }}
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

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
        add_header X-Frame-Options SAMEORIGIN always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Content-Security-Policy "frame-ancestors 'self'" always;

        # File upload size
        client_max_body_size 50M;

        # Rate limiting for API endpoints
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://mattermost_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Frame-Options SAMEORIGIN;
        }

        # Rate limiting for login endpoints
        location /api/v4/users/login {
            limit_req zone=login burst=5 nodelay;
            proxy_pass http://mattermost_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # WebSocket support
        location ~ /api/v[0-9]+/(users/)?websocket$ {
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Frame-Options SAMEORIGIN;
            proxy_buffers 256 16k;
            proxy_buffer_size 16k;
            client_body_timeout 60;
            send_timeout 300;
            lingering_timeout 5;
            proxy_connect_timeout 90;
            proxy_send_timeout 300;
            proxy_read_timeout 90s;
            proxy_pass http://mattermost_backend;
        }

        # Main application
        location / {
            proxy_pass http://mattermost_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Frame-Options SAMEORIGIN;
            
            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }

        # Health check endpoint
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
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
