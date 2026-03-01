// constants.go - Single source of truth for all Mattermost-related constants.
// CLAUDE.md P0 Rule #12: NEVER use hardcoded literal values in code.

// Package mattermost provides Mattermost team collaboration platform
// deployment, configuration, and lifecycle management for Eos.
package mattermost

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// --- Directory constants ---

const (
	// ServiceName is the canonical name used in logs, secrets, and Consul.
	ServiceName = "mattermost"

	// InstallDir is where the Docker Compose deployment lives.
	// RATIONALE: Follows Eos convention of /opt/[service] for Docker Compose services.
	InstallDir = "/opt/mattermost"

	// CloneTempDir is the temporary directory used during git clone.
	CloneTempDir = "/opt/mattermost-tmp"

	// ComposeFileName is the docker-compose file name inside InstallDir.
	ComposeFileName = "docker-compose.yml"

	// EnvFileName is the .env file name inside InstallDir.
	EnvFileName = ".env"

	// EnvExampleFileName is the template .env shipped with the Mattermost Docker repo.
	EnvExampleFileName = "env.example"

	// VolumesBaseDir is the base for Mattermost volumes relative to InstallDir.
	VolumesBaseDir = "volumes/app/mattermost"
)

// --- Git ---

const (
	// RepoURL is the official Mattermost Docker deployment repository.
	RepoURL = "https://github.com/mattermost/docker"
)

// --- Network ---

const (
	// DefaultPort is the Eos-standard port for Mattermost.
	// Uses the value from shared.PortMattermost (8017) as single source of truth.
	DefaultPort = shared.PortMattermost

	// InternalPort is the port Mattermost listens on inside the container.
	InternalPort = 8065

	// PostgresPort is the standard PostgreSQL port.
	PostgresPort = 5432

	// maxValidPort is the highest valid TCP port number.
	maxValidPort = 65535
)

// --- Database ---

const (
	// PostgresUser is the default database user.
	PostgresUser = "mmuser"

	// PostgresDB is the default database name.
	PostgresDB = "mattermost"
)

// --- Container ownership ---

const (
	// ContainerUID is the UID Mattermost runs as inside the container.
	// RATIONALE: Official Mattermost Docker image uses UID 2000.
	// SECURITY: Volumes must be owned by this UID for the container to write.
	ContainerUID = 2000

	// ContainerGID is the GID Mattermost runs as inside the container.
	ContainerGID = 2000

)

// ContainerOwnership is the chown argument for Mattermost volumes.
// Derived from ContainerUID and ContainerGID to prevent drift.
var ContainerOwnership = fmt.Sprintf("%d:%d", ContainerUID, ContainerGID)

// --- Permissions ---

var (
	// InstallDirPerm is the permission for the installation directory.
	// RATIONALE: Standard service directory accessible by root.
	// SECURITY: Prevents unprivileged modification of deployment config.
	InstallDirPerm = shared.ServiceDirPerm

	// VolumeDirPerm is the permission for volume subdirectories.
	// RATIONALE: Mattermost container needs write access via UID 2000.
	// SECURITY: Owner-writable, group/other readable for container access.
	VolumeDirPerm = os.FileMode(0755)

	// EnvFilePerm is the permission for the .env file containing secrets.
	// RATIONALE: Contains database password - restricted to owner.
	// SECURITY: Prevents secret leakage via file read.
	EnvFilePerm = shared.SecureConfigFilePerm
)

// --- Volume subdirectories ---

// VolumeSubdirs lists the required subdirectories for Mattermost volumes.
// These must exist and be owned by ContainerUID:ContainerGID.
var VolumeSubdirs = []string{
	"config",
	"data",
	"logs",
	"plugins",
	"client/plugins",
	"bleve-indexes",
}

// --- Default .env overrides ---

// DefaultEnvOverrides holds the standard .env key/value overrides
// applied when patching the Mattermost env.example file.
var DefaultEnvOverrides = map[string]string{
	"DOMAIN": "localhost",
	"TZ":     "UTC",
}

// --- Support ---

const (
	// DefaultSupportEmail is the support contact shown in Mattermost UI.
	DefaultSupportEmail = "support@cybermonkey.net.au"
)
