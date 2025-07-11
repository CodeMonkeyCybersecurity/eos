// Package nomad provides Nomad job generation for ClusterFuzz
package nomad

import (
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/clusterfuzz"
)

// GenerateJobs generates Nomad job files for ClusterFuzz deployment.
// It follows the Assess → Intervene → Evaluate pattern.
func GenerateJobs(config *clusterfuzz.Config) error {
	// ASSESS - Define the core job template
	coreJobTemplate := `job "clusterfuzz-core" {
  datacenters = ["dc1"]
  type = "service"
  
  update {
    max_parallel = 1
    min_healthy_time = "10s"
    healthy_deadline = "5m"
    auto_revert = true
  }

  {{if eq .DatabaseBackend "postgresql"}}
  group "database" {
    count = 1
    
    network {
      port "db" {
        static = 5432
      }
    }
    
    service {
      name = "clusterfuzz-postgres"
      port = "db"
      
      check {
        type = "tcp"
        interval = "10s"
        timeout = "2s"
      }
    }
    
    task "postgres" {
      driver = "docker"
      
      config {
        image = "postgres:15"
        ports = ["db"]
        
        volumes = [
          "local/init:/docker-entrypoint-initdb.d"
        ]
      }
      
      template {
        data = <<EOF
#!/bin/bash
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE DATABASE clusterfuzz;
    GRANT ALL PRIVILEGES ON DATABASE clusterfuzz TO $POSTGRES_USER;
EOSQL
EOF
        destination = "local/init/01-create-db.sh"
        perms = "755"
      }
      
      env {
        POSTGRES_USER = "{{.DatabaseConfig.Username}}"
        POSTGRES_PASSWORD = "{{.DatabaseConfig.Password}}"
        POSTGRES_DB = "{{.DatabaseConfig.Database}}"
      }
      
      resources {
        cpu    = 2000
        memory = 4096
      }
    }
  }
  {{end}}

  {{if eq .QueueBackend "redis"}}
  group "queue" {
    count = 1
    
    network {
      port "redis" {
        static = 6379
      }
    }
    
    service {
      name = "clusterfuzz-redis"
      port = "redis"
      
      check {
        type = "tcp"
        interval = "10s"
        timeout = "2s"
      }
    }
    
    task "redis" {
      driver = "docker"
      
      config {
        image = "redis:7-alpine"
        ports = ["redis"]
        command = "redis-server"
        args = ["--requirepass", "{{.QueueConfig.Password}}"]
      }
      
      resources {
        cpu    = 500
        memory = 1024
      }
    }
  }
  {{end}}

  {{if eq .StorageBackend "minio"}}
  group "storage" {
    count = 1
    
    network {
      port "minio" {
        static = 9000
      }
      port "console" {
        static = 9001
      }
    }
    
    service {
      name = "clusterfuzz-minio"
      port = "minio"
      
      check {
        type = "http"
        path = "/minio/health/live"
        interval = "10s"
        timeout = "2s"
      }
    }
    
    task "minio" {
      driver = "docker"
      
      config {
        image = "minio/minio:latest"
        ports = ["minio", "console"]
        args = ["server", "/data", "--console-address", ":9001"]
      }
      
      env {
        MINIO_ROOT_USER = "{{.S3Config.AccessKey}}"
        MINIO_ROOT_PASSWORD = "{{.S3Config.SecretKey}}"
      }
      
      resources {
        cpu    = 1000
        memory = 2048
      }
    }
  }
  {{end}}
}`

	// INTERVENE - Parse and execute template
	tmpl, err := template.New("core-job").Parse(coreJobTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse core job template: %w", err)
	}

	// Create output file
	outputPath := filepath.Join(config.ConfigDir, "jobs", "clusterfuzz-core.nomad")
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create job file: %w", err)
	}
	defer file.Close()

	// EVALUATE - Execute template
	if err := tmpl.Execute(file, config); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	// Generate bot job
	if err := generateBotJob(config); err != nil {
		return fmt.Errorf("failed to generate bot job: %w", err)
	}

	// Generate web job
	if err := generateWebJob(config); err != nil {
		return fmt.Errorf("failed to generate web job: %w", err)
	}

	return nil
}

// generateBotJob generates the bot deployment job
func generateBotJob(config *clusterfuzz.Config) error {
	botJobTemplate := `job "clusterfuzz-bots" {
  datacenters = ["dc1"]
  type = "batch"
  
  parameterized {
    payload = "optional"
  }
  
  group "bot" {
    count = {{.BotCount}}
    
    task "fuzzer" {
      driver = "docker"
      
      config {
        image = "clusterfuzz/bot:latest"
        
        volumes = [
          "local/config:/config"
        ]
      }
      
      template {
        data = <<EOF
{{template "bot-env" .}}
EOF
        destination = "local/config/bot.env"
        env = true
      }
      
      resources {
        cpu    = 2000
        memory = 4096
      }
    }
  }
  
  {{if gt .PreemptibleBotCount 0}}
  group "preemptible-bot" {
    count = {{.PreemptibleBotCount}}
    
    constraint {
      attribute = "${node.class}"
      value     = "preemptible"
    }
    
    task "fuzzer" {
      driver = "docker"
      
      config {
        image = "clusterfuzz/bot:latest"
        
        volumes = [
          "local/config:/config"
        ]
      }
      
      template {
        data = <<EOF
{{template "bot-env" .}}
EOF
        destination = "local/config/bot.env"
        env = true
      }
      
      resources {
        cpu    = 2000
        memory = 4096
      }
    }
  }
  {{end}}
}`

	// Define bot environment template
	botEnvTemplate := `{{define "bot-env"}}
CLUSTERFUZZ_DB_HOST={{.DatabaseConfig.Host}}
CLUSTERFUZZ_DB_PORT={{.DatabaseConfig.Port}}
CLUSTERFUZZ_DB_NAME={{.DatabaseConfig.Database}}
CLUSTERFUZZ_DB_USER={{.DatabaseConfig.Username}}
CLUSTERFUZZ_DB_PASS={{.DatabaseConfig.Password}}
CLUSTERFUZZ_QUEUE_HOST={{.QueueConfig.Host}}
CLUSTERFUZZ_QUEUE_PORT={{.QueueConfig.Port}}
{{if .QueueConfig.Password}}CLUSTERFUZZ_QUEUE_PASS={{.QueueConfig.Password}}{{end}}
{{if .S3Config.Endpoint}}
CLUSTERFUZZ_S3_ENDPOINT={{.S3Config.Endpoint}}
CLUSTERFUZZ_S3_ACCESS_KEY={{.S3Config.AccessKey}}
CLUSTERFUZZ_S3_SECRET_KEY={{.S3Config.SecretKey}}
CLUSTERFUZZ_S3_BUCKET={{.S3Config.Bucket}}
{{end}}
{{end}}`

	// Parse templates
	tmpl := template.New("bot-job")
	tmpl, err := tmpl.Parse(botEnvTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse bot env template: %w", err)
	}
	tmpl, err = tmpl.Parse(botJobTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse bot job template: %w", err)
	}

	// Create output file
	outputPath := filepath.Join(config.ConfigDir, "jobs", "clusterfuzz-bots.nomad")
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create bot job file: %w", err)
	}
	defer file.Close()

	// Execute template
	return tmpl.Execute(file, config)
}

// generateWebJob generates the web UI job
func generateWebJob(config *clusterfuzz.Config) error {
	webJobTemplate := `job "clusterfuzz-web" {
  datacenters = ["dc1"]
  type = "service"
  
  group "web" {
    count = 1
    
    network {
      port "http" {
        to = 8080
      }
    }
    
    service {
      name = "clusterfuzz-web"
      port = "http"
      
      tags = [
        "traefik.enable=true",
        "traefik.http.routers.clusterfuzz.rule=Host(` + "`" + `{{.Domain}}` + "`" + `)",
        "traefik.http.routers.clusterfuzz.tls=true",
        "traefik.http.routers.clusterfuzz.tls.certresolver=letsencrypt"
      ]
      
      check {
        type = "http"
        path = "/health"
        interval = "10s"
        timeout = "2s"
      }
    }
    
    task "web" {
      driver = "docker"
      
      config {
        image = "clusterfuzz/web:latest"
        ports = ["http"]
      }
      
      env {
        CLUSTERFUZZ_DB_HOST = "{{.DatabaseConfig.Host}}"
        CLUSTERFUZZ_DB_PORT = "{{.DatabaseConfig.Port}}"
        CLUSTERFUZZ_DB_NAME = "{{.DatabaseConfig.Database}}"
        CLUSTERFUZZ_DB_USER = "{{.DatabaseConfig.Username}}"
        CLUSTERFUZZ_DB_PASS = "{{.DatabaseConfig.Password}}"
        {{if .Domain}}CLUSTERFUZZ_DOMAIN = "{{.Domain}}"{{end}}
      }
      
      resources {
        cpu    = 1000
        memory = 2048
      }
    }
  }
}`

	// Parse and execute template
	tmpl, err := template.New("web-job").Parse(webJobTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse web job template: %w", err)
	}

	outputPath := filepath.Join(config.ConfigDir, "jobs", "clusterfuzz-web.nomad")
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create web job file: %w", err)
	}
	defer file.Close()

	return tmpl.Execute(file, config)
}