// pkg/gitea/constants.go
// Constants for Gitea Git service configuration

package gitea

import "github.com/CodeMonkeyCybersecurity/eos/pkg/shared"

const (
	// ServiceName is the systemd service name for Gitea
	ServiceName = "gitea"

	// GiteaDir is the installation directory for Gitea
	// RATIONALE: Follows Eos convention of /opt/[service]
	GiteaDir = "/opt/gitea"

	// GiteaComposeFile is the docker-compose.yml filename
	GiteaComposeFile = "docker-compose.yml"

	// GiteaDataDir is the data directory for Gitea repositories and database
	GiteaDataDir = "/opt/gitea/data"

	// GiteaConfigDir is the configuration directory
	GiteaConfigDir = "/opt/gitea/config"

	// GiteaDBDir is the database directory
	GiteaDBDir = "/opt/gitea/db"

	// GiteaPort is the HTTP port for Gitea web interface
	// NOTE: References shared.PortGitea to avoid circular import
	GiteaPort = shared.PortGitea

	// GiteaSSHPort is the SSH port for Git operations
	GiteaSSHPort = 2222

	// GiteaImage is the default Docker image
	GiteaImage = "gitea/gitea:latest"

	// GiteaDBImage is the PostgreSQL database image
	GiteaDBImage = "postgres:14"

	// DirPermStandard is the standard directory permission
	// RATIONALE: Owner rwx, group rx, other rx - allows service account access
	// SECURITY: Not sensitive directories, world-readable OK
	DirPermStandard = 0755

	// FilePermStandard is the standard file permission
	// RATIONALE: Owner rw, group r, other r - standard config files
	// SECURITY: Not sensitive files, world-readable OK
	FilePermStandard = 0644

	// SecretFilePermStandard is the permission for files containing secrets
	// RATIONALE: Owner rw only - prevents unauthorized access to credentials
	// SECURITY: PCI-DSS 8.2.1, SOC2 CC6.1 compliance
	// THREAT MODEL: Prevents local privilege escalation via credential theft
	SecretFilePermStandard = 0600
)

// DefaultComposeYAML returns the default docker-compose.yml content for Gitea
// SECURITY: Uses environment variables for secrets instead of hardcoding
func DefaultComposeYAML() string {
	return `version: "3"

networks:
  gitea:
    external: false

services:
  server:
    image: gitea/gitea:latest
    container_name: gitea
    environment:
      - USER_UID=1000
      - USER_GID=1000
      - GITEA__database__DB_TYPE=postgres
      - GITEA__database__HOST=db:5432
      - GITEA__database__NAME=gitea
      - GITEA__database__USER=gitea
      - GITEA__database__PASSWD=${GITEA_DB_PASSWORD}
    restart: always
    networks:
      - gitea
    volumes:
      - ./data:/data
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
    ports:
      - "` + shared.PortToString(shared.PortGitea) + `:3000"
      - "2222:22"
    depends_on:
      - db

  db:
    image: postgres:14
    restart: always
    environment:
      - POSTGRES_USER=gitea
      - POSTGRES_PASSWORD=${GITEA_DB_PASSWORD}
      - POSTGRES_DB=gitea
    networks:
      - gitea
    volumes:
      - ./db:/var/lib/postgresql/data
`
}
