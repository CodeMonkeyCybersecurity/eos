job "mattermost" {
  datacenters = ["dc1"]
  type        = "service"

  group "mattermost" {
    count = 1

    network {
      port "http" {
        static = 8065
      }
    }

    task "mattermost" {
      driver = "docker"

      config {
        image = "mattermost/mattermost-team-edition:latest"
        ports = ["http"]
        
        volumes = [
          "mattermost-data:/mattermost/data",
          "mattermost-logs:/mattermost/logs",
          "mattermost-config:/mattermost/config",
          "mattermost-plugins:/mattermost/plugins"
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
        MM_SQLSETTINGS_DRIVERNAME = "postgres"
        MM_SQLSETTINGS_DATASOURCE = "postgres://mattermost:${MATTERMOST_DB_PASSWORD}@postgres.service.consul:5432/mattermost?sslmode=disable&connect_timeout=10"
        MM_SERVICESETTINGS_SITEURL = "https://chat.${DOMAIN}"
        MM_SERVICESETTINGS_LISTENADDRESS = ":8065"
        
        # Authentication
        MM_EMAILSETTINGS_ENABLESIGNUPWITHEMAIL = "false"
        MM_EMAILSETTINGS_ENABLESIGNINWITHEMAIL = "true"
        MM_EMAILSETTINGS_ENABLESIGNINWITHUSERNAME = "true"
        
        # OAuth2 / Authentik integration
        MM_GITLABSETTINGS_ENABLE = "true"
        MM_GITLABSETTINGS_ID = "${OAUTH_CLIENT_ID}"
        MM_GITLABSETTINGS_SECRET = "${OAUTH_CLIENT_SECRET}"
        MM_GITLABSETTINGS_SCOPE = "openid profile email"
        MM_GITLABSETTINGS_AUTHENDPOINT = "https://auth.${DOMAIN}/application/o/authorize/"
        MM_GITLABSETTINGS_TOKENENDPOINT = "https://auth.${DOMAIN}/application/o/token/"
        MM_GITLABSETTINGS_USERAPIENDPOINT = "https://auth.${DOMAIN}/application/o/userinfo/"
        
        # File storage
        MM_FILESETTINGS_DRIVERNAME = "local"
        MM_FILESETTINGS_DIRECTORY = "/mattermost/data/"
        MM_FILESETTINGS_MAXFILESIZE = "104857600" # 100MB
        
        # Plugins
        MM_PLUGINSETTINGS_ENABLE = "true"
        MM_PLUGINSETTINGS_ENABLEUPLOADS = "true"
        
        # Performance
        MM_SERVICESETTINGS_GOROUTINEHEALTHYTHRESHOLD = "-1"
        MM_SQLSETTINGS_MAXIDLECONNS = "20"
        MM_SQLSETTINGS_MAXOPENCONNS = "300"
        MM_SQLSETTINGS_TRACE = "false"
        MM_CACHEENABLED = "true"
        MM_CACHESIZEINMB = "256"
      }

      resources {
        cpu    = 1000
        memory = 2048
      }

      service {
        name = "mattermost"
        port = "http"
        tags = ["messaging", "chat", "ui"]

        check {
          type     = "http"
          path     = "/api/v4/system/ping"
          interval = "30s"
          timeout  = "5s"
        }
      }
    }
  }
}