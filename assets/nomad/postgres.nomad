job "postgres" {
  datacenters = ["dc1"]
  type        = "service"

  group "postgres" {
    count = 1

    network {
      port "postgres" {
        static = 5432
      }
    }

    task "postgres" {
      driver = "docker"

      config {
        image = "postgres:15-alpine"
        ports = ["postgres"]
        
        volumes = [
          "postgres-data:/var/lib/postgresql/data",
          "local/init.sql:/docker-entrypoint-initdb.d/init.sql"
        ]

        logging {
          type = "json-file"
          config {
            max-size = "10m"
            max-file = "3"
          }
        }
      }

      env {
        POSTGRES_USER     = "postgres"
        POSTGRES_PASSWORD = "${POSTGRES_PASSWORD}"
        POSTGRES_DB       = "eos"
        PGDATA           = "/var/lib/postgresql/data/pgdata"
      }

      template {
        data = <<EOH
-- Create databases for services
CREATE DATABASE grafana;
CREATE DATABASE authentik;
CREATE DATABASE mattermost;
CREATE DATABASE wazuh;

-- Create users
CREATE USER grafana WITH ENCRYPTED PASSWORD '${GRAFANA_DB_PASSWORD}';
CREATE USER authentik WITH ENCRYPTED PASSWORD '${AUTHENTIK_DB_PASSWORD}';
CREATE USER mattermost WITH ENCRYPTED PASSWORD '${MATTERMOST_DB_PASSWORD}';
CREATE USER wazuh WITH ENCRYPTED PASSWORD '${WAZUH_DB_PASSWORD}';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE grafana TO grafana;
GRANT ALL PRIVILEGES ON DATABASE authentik TO authentik;
GRANT ALL PRIVILEGES ON DATABASE mattermost TO mattermost;
GRANT ALL PRIVILEGES ON DATABASE wazuh TO wazuh;

-- Create schemas
\c grafana;
CREATE SCHEMA IF NOT EXISTS grafana AUTHORIZATION grafana;

\c authentik;
CREATE SCHEMA IF NOT EXISTS authentik AUTHORIZATION authentik;

\c mattermost;
CREATE SCHEMA IF NOT EXISTS mattermost AUTHORIZATION mattermost;

\c wazuh;
CREATE SCHEMA IF NOT EXISTS wazuh AUTHORIZATION wazuh;

-- Performance tuning
ALTER SYSTEM SET max_connections = 100;
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;
ALTER SYSTEM SET work_mem = '4MB';
ALTER SYSTEM SET min_wal_size = '1GB';
ALTER SYSTEM SET max_wal_size = '4GB';
EOH
        destination = "local/init.sql"
      }

      resources {
        cpu    = 1000
        memory = 2048
      }

      service {
        name = "postgres"
        port = "postgres"
        tags = ["database", "sql"]

        check {
          type     = "script"
          command  = "pg_isready"
          args     = ["-h", "localhost", "-p", "5432", "-U", "postgres"]
          interval = "30s"
          timeout  = "5s"
        }
      }
    }
  }
}