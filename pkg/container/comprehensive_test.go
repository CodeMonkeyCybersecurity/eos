package container

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestComposeFile_Structure(t *testing.T) {
	tests := []struct {
		name     string
		compose  *ComposeFile
		validate func(t *testing.T, cf *ComposeFile)
	}{
		{
			name: "complete compose file",
			compose: &ComposeFile{
				Services: map[string]Service{
					"web": {
						Image:         "nginx:latest",
						ContainerName: "web-server",
						Ports:         []string{"80:80", "443:443"},
						Environment: map[string]string{
							"NODE_ENV": "production",
							"API_KEY":  "secret123",
						},
						Volumes:   []string{"./data:/usr/share/nginx/html", "logs:/var/log/nginx"},
						DependsOn: []string{"db", "cache"},
						Restart:   "unless-stopped",
						Networks:  []string{"frontend", "backend"},
					},
					"db": {
						Image:         "postgres:13",
						ContainerName: "database",
						Ports:         []string{"5432:5432"},
						Environment: map[string]string{
							"POSTGRES_DB":       "myapp",
							"POSTGRES_USER":     "admin",
							"POSTGRES_PASSWORD": "password",
						},
						Volumes:  []string{"db-data:/var/lib/postgresql/data"},
						Restart:  "always",
						Networks: []string{"backend"},
					},
				},
				Volumes: map[string]interface{}{
					"db-data": nil,
					"logs": map[string]interface{}{
						"driver": "local",
					},
				},
				Networks: map[string]interface{}{
					"frontend": nil,
					"backend": map[string]interface{}{
						"internal": true,
					},
				},
			},
			validate: func(t *testing.T, cf *ComposeFile) {
				assert.Len(t, cf.Services, 2)
				assert.Contains(t, cf.Services, "web")
				assert.Contains(t, cf.Services, "db")

				// Validate web service
				web := cf.Services["web"]
				assert.Equal(t, "nginx:latest", web.Image)
				assert.Equal(t, "web-server", web.ContainerName)
				assert.Len(t, web.Ports, 2)
				assert.Len(t, web.Environment, 2)
				assert.Len(t, web.Volumes, 2)
				assert.Len(t, web.DependsOn, 2)
				assert.Equal(t, "unless-stopped", web.Restart)
				assert.Len(t, web.Networks, 2)

				// Validate volumes
				assert.Len(t, cf.Volumes, 2)
				assert.Contains(t, cf.Volumes, "db-data")
				assert.Contains(t, cf.Volumes, "logs")

				// Validate networks
				assert.Len(t, cf.Networks, 2)
				assert.Contains(t, cf.Networks, "frontend")
				assert.Contains(t, cf.Networks, "backend")
			},
		},
		{
			name: "minimal compose file",
			compose: &ComposeFile{
				Services: map[string]Service{
					"app": {
						Image: "alpine:3.14",
					},
				},
			},
			validate: func(t *testing.T, cf *ComposeFile) {
				assert.Len(t, cf.Services, 1)
				assert.Contains(t, cf.Services, "app")

				app := cf.Services["app"]
				assert.Equal(t, "alpine:3.14", app.Image)
				assert.Empty(t, app.ContainerName)
				assert.Empty(t, app.Ports)
				assert.Empty(t, app.Environment)
				assert.Empty(t, app.Volumes)
				assert.Empty(t, app.DependsOn)
				assert.Empty(t, app.Restart)
				assert.Empty(t, app.Networks)

				assert.Empty(t, cf.Volumes)
				assert.Empty(t, cf.Networks)
			},
		},
		{
			name: "empty compose file",
			compose: &ComposeFile{
				Services: map[string]Service{},
				Volumes:  map[string]interface{}{},
				Networks: map[string]interface{}{},
			},
			validate: func(t *testing.T, cf *ComposeFile) {
				assert.Empty(t, cf.Services)
				assert.Empty(t, cf.Volumes)
				assert.Empty(t, cf.Networks)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.validate(t, tt.compose)
		})
	}
}

func TestComposeFile_YAMLMarshaling(t *testing.T) {
	tests := []struct {
		name    string
		compose *ComposeFile
	}{
		{
			name: "marshal and unmarshal",
			compose: &ComposeFile{
				Services: map[string]Service{
					"redis": {
						Image:         "redis:6-alpine",
						ContainerName: "cache",
						Ports:         []string{"6379:6379"},
						Environment: map[string]string{
							"REDIS_PASSWORD": "secret",
						},
						Volumes: []string{"redis-data:/data"},
						Restart: "always",
					},
				},
				Volumes: map[string]interface{}{
					"redis-data": nil,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to YAML
			data, err := yaml.Marshal(tt.compose)
			require.NoError(t, err)
			assert.NotEmpty(t, data)

			// Unmarshal back
			var decoded ComposeFile
			err = yaml.Unmarshal(data, &decoded)
			require.NoError(t, err)

			// Verify services
			assert.Equal(t, len(tt.compose.Services), len(decoded.Services))
			for name, service := range tt.compose.Services {
				decodedService, exists := decoded.Services[name]
				assert.True(t, exists)
				assert.Equal(t, service.Image, decodedService.Image)
				assert.Equal(t, service.ContainerName, decodedService.ContainerName)
				assert.Equal(t, service.Ports, decodedService.Ports)
				assert.Equal(t, service.Environment, decodedService.Environment)
				assert.Equal(t, service.Volumes, decodedService.Volumes)
				assert.Equal(t, service.Restart, decodedService.Restart)
			}
		})
	}
}

func TestService_Structure(t *testing.T) {
	tests := []struct {
		name     string
		service  Service
		validate func(t *testing.T, s Service)
	}{
		{
			name: "complete service",
			service: Service{
				Image:         "mysql:8.0",
				ContainerName: "mysql-db",
				Ports:         []string{"3306:3306", "33060:33060"},
				Environment: map[string]string{
					"MYSQL_ROOT_PASSWORD": "rootpass",
					"MYSQL_DATABASE":      "testdb",
					"MYSQL_USER":          "testuser",
					"MYSQL_PASSWORD":      "testpass",
				},
				Volumes:   []string{"mysql-data:/var/lib/mysql", "./init.sql:/docker-entrypoint-initdb.d/init.sql"},
				DependsOn: []string{"config-server"},
				Restart:   "unless-stopped",
				Networks:  []string{"database-net"},
			},
			validate: func(t *testing.T, s Service) {
				assert.Equal(t, "mysql:8.0", s.Image)
				assert.Equal(t, "mysql-db", s.ContainerName)
				assert.Len(t, s.Ports, 2)
				assert.Contains(t, s.Ports, "3306:3306")
				assert.Len(t, s.Environment, 4)
				assert.Equal(t, "rootpass", s.Environment["MYSQL_ROOT_PASSWORD"])
				assert.Len(t, s.Volumes, 2)
				assert.Len(t, s.DependsOn, 1)
				assert.Equal(t, "unless-stopped", s.Restart)
				assert.Len(t, s.Networks, 1)
			},
		},
		{
			name: "minimal service",
			service: Service{
				Image: "busybox:latest",
			},
			validate: func(t *testing.T, s Service) {
				assert.Equal(t, "busybox:latest", s.Image)
				assert.Empty(t, s.ContainerName)
				assert.Empty(t, s.Ports)
				assert.Empty(t, s.Environment)
				assert.Empty(t, s.Volumes)
				assert.Empty(t, s.DependsOn)
				assert.Empty(t, s.Restart)
				assert.Empty(t, s.Networks)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.validate(t, tt.service)
		})
	}
}

func TestDockerConstants(t *testing.T) {
	// Test network constants
	assert.Equal(t, "arachne-net", DockerNetworkName)
	assert.Equal(t, "172.30.0.0/16", DockerIPv4Subnet)
	assert.Equal(t, "fd00:dead:beef::/64", DockerIPv6Subnet)

	// Validate subnet formats
	assert.Contains(t, DockerIPv4Subnet, "/")
	assert.Contains(t, DockerIPv6Subnet, "/")
	assert.Contains(t, DockerIPv6Subnet, "::")
}

func TestComposeFile_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		compose  *ComposeFile
		validate func(t *testing.T, cf *ComposeFile)
	}{
		{
			name: "service with special characters",
			compose: &ComposeFile{
				Services: map[string]Service{
					"my-service_1": {
						Image:         "registry.example.com:5000/my-app:v1.2.3",
						ContainerName: "my_service-1",
						Environment: map[string]string{
							"VAR_WITH-DASH":  "value",
							"VAR.WITH.DOT":   "value",
							"VAR_WITH_UNDER": "value",
						},
					},
				},
			},
			validate: func(t *testing.T, cf *ComposeFile) {
				assert.Len(t, cf.Services, 1)
				service := cf.Services["my-service_1"]
				assert.NotEmpty(t, service.Image)
				assert.Len(t, service.Environment, 3)
			},
		},
		{
			name: "service with port ranges",
			compose: &ComposeFile{
				Services: map[string]Service{
					"ports": {
						Image: "test:latest",
						Ports: []string{
							"8080:80",
							"9000-9005:9000-9005",
							"shared.GetInternalHostname:3000:3000",
							"[::1]:4000:4000",
						},
					},
				},
			},
			validate: func(t *testing.T, cf *ComposeFile) {
				service := cf.Services["ports"]
				assert.Len(t, service.Ports, 4)
			},
		},
		{
			name: "service with volume options",
			compose: &ComposeFile{
				Services: map[string]Service{
					"volumes": {
						Image: "test:latest",
						Volumes: []string{
							"./relative/path:/container/path",
							"/absolute/path:/container/path",
							"named-volume:/data",
							"./file.conf:/etc/app.conf:ro",
							"tmpfs:/tmp",
						},
					},
				},
			},
			validate: func(t *testing.T, cf *ComposeFile) {
				service := cf.Services["volumes"]
				assert.Len(t, service.Volumes, 5)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.validate(t, tt.compose)
		})
	}
}

func TestService_RestartPolicies(t *testing.T) {
	validPolicies := []string{
		"no",
		"always",
		"on-failure",
		"unless-stopped",
		"", // empty is valid
	}

	for _, policy := range validPolicies {
		t.Run("restart_"+policy, func(t *testing.T) {
			s := Service{
				Image:   "test:latest",
				Restart: policy,
			}
			assert.Equal(t, policy, s.Restart)
		})
	}
}

func TestComposeFile_ComplexNetworks(t *testing.T) {
	cf := &ComposeFile{
		Services: map[string]Service{
			"app": {
				Image:    "app:latest",
				Networks: []string{"frontend", "backend", "monitoring"},
			},
		},
		Networks: map[string]interface{}{
			"frontend": map[string]interface{}{
				"driver": "bridge",
			},
			"backend": map[string]interface{}{
				"driver":   "bridge",
				"internal": true,
			},
			"monitoring": map[string]interface{}{
				"driver": "overlay",
				"ipam": map[string]interface{}{
					"config": []map[string]interface{}{
						{
							"subnet": "192.168.10.0/24",
						},
					},
				},
			},
		},
	}

	assert.Len(t, cf.Networks, 3)
	assert.Contains(t, cf.Networks, "frontend")
	assert.Contains(t, cf.Networks, "backend")
	assert.Contains(t, cf.Networks, "monitoring")

	// Check backend network is internal
	backend := cf.Networks["backend"].(map[string]interface{})
	assert.Equal(t, true, backend["internal"])
}

func TestComposeFile_ComplexVolumes(t *testing.T) {
	cf := &ComposeFile{
		Services: map[string]Service{
			"db": {
				Image:   "postgres:13",
				Volumes: []string{"db-data:/var/lib/postgresql/data"},
			},
		},
		Volumes: map[string]interface{}{
			"db-data": map[string]interface{}{
				"driver": "local",
				"driver_opts": map[string]interface{}{
					"type":   "nfs",
					"o":      "addr=10.0.0.1,rw",
					"device": ":/exports/docker/db",
				},
			},
		},
	}

	assert.Len(t, cf.Volumes, 1)
	assert.Contains(t, cf.Volumes, "db-data")

	// Check volume configuration
	dbData := cf.Volumes["db-data"].(map[string]interface{})
	assert.Equal(t, "local", dbData["driver"])
	assert.Contains(t, dbData, "driver_opts")
}

func TestService_EnvironmentEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "empty values",
			env: map[string]string{
				"EMPTY_VAR": "",
				"NORMAL":    "value",
			},
		},
		{
			name: "special characters in values",
			env: map[string]string{
				"SPECIAL": "value=with=equals",
				"QUOTED":  `"quoted value"`,
				"SPACES":  "value with spaces",
				"NEWLINE": "value\nwith\nnewlines",
			},
		},
		{
			name: "numeric values",
			env: map[string]string{
				"PORT":    "8080",
				"TIMEOUT": "30",
				"FLOAT":   "3.14",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Service{
				Image:       "test:latest",
				Environment: tt.env,
			}

			assert.Equal(t, len(tt.env), len(s.Environment))
			for k, v := range tt.env {
				assert.Equal(t, v, s.Environment[k])
			}
		})
	}
}

func TestService_Dependencies(t *testing.T) {
	tests := []struct {
		name      string
		dependsOn []string
	}{
		{
			name:      "single dependency",
			dependsOn: []string{"db"},
		},
		{
			name:      "multiple dependencies",
			dependsOn: []string{"db", "cache", "queue"},
		},
		{
			name:      "no dependencies",
			dependsOn: []string{},
		},
		{
			name:      "duplicate dependencies",
			dependsOn: []string{"db", "db", "cache"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Service{
				Image:     "app:latest",
				DependsOn: tt.dependsOn,
			}

			assert.Equal(t, tt.dependsOn, s.DependsOn)
		})
	}
}
