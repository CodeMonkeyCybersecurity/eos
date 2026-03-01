package mattermost

import (
	"fmt"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// --- Unit tests: constants consistency (test pyramid: unit, 70% weight) ---

func TestDefaultPortMatchesShared(t *testing.T) {
	// RATIONALE: Port inconsistency was a root cause bug (8065 vs 8017).
	// This test enforces single source of truth.
	if DefaultPort != shared.PortMattermost {
		t.Errorf("DefaultPort (%d) != shared.PortMattermost (%d): port constants are inconsistent",
			DefaultPort, shared.PortMattermost)
	}
}

func TestServiceNameIsLowercase(t *testing.T) {
	if ServiceName != "mattermost" {
		t.Errorf("ServiceName should be 'mattermost', got %q", ServiceName)
	}
}

func TestInstallDirStartsWithOpt(t *testing.T) {
	// RATIONALE: Eos convention is /opt/[service] for Docker Compose services.
	if InstallDir != "/opt/mattermost" {
		t.Errorf("InstallDir should be '/opt/mattermost', got %q", InstallDir)
	}
}

func TestContainerUIDGIDMatch(t *testing.T) {
	// RATIONALE: Mattermost Docker image uses UID/GID 2000.
	// Mismatch causes permission denied errors.
	if ContainerUID != 2000 {
		t.Errorf("ContainerUID should be 2000, got %d", ContainerUID)
	}
	if ContainerGID != 2000 {
		t.Errorf("ContainerGID should be 2000, got %d", ContainerGID)
	}
}

func TestContainerOwnershipDerivedFromUIDs(t *testing.T) {
	// ContainerOwnership must be derived from ContainerUID:ContainerGID
	// to prevent drift if either constant changes.
	expected := fmt.Sprintf("%d:%d", ContainerUID, ContainerGID)
	if ContainerOwnership != expected {
		t.Errorf("ContainerOwnership (%q) does not match derived %q from UID=%d GID=%d",
			ContainerOwnership, expected, ContainerUID, ContainerGID)
	}
}

func TestVolumeSubdirsNotEmpty(t *testing.T) {
	if len(VolumeSubdirs) == 0 {
		t.Error("VolumeSubdirs should not be empty")
	}
}

func TestVolumeSubdirsContainsCriticalDirs(t *testing.T) {
	required := []string{"config", "data", "logs", "plugins"}
	for _, req := range required {
		found := false
		for _, sub := range VolumeSubdirs {
			if sub == req {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("VolumeSubdirs missing required subdirectory %q", req)
		}
	}
}

func TestDefaultEnvOverridesHasDomain(t *testing.T) {
	if _, ok := DefaultEnvOverrides["DOMAIN"]; !ok {
		t.Error("DefaultEnvOverrides must include DOMAIN key")
	}
}

func TestPostgresPortIsStandard(t *testing.T) {
	if PostgresPort != 5432 {
		t.Errorf("PostgresPort should be 5432 (standard PostgreSQL), got %d", PostgresPort)
	}
}

func TestInternalPortIsStandard(t *testing.T) {
	// Mattermost default internal port
	if InternalPort != 8065 {
		t.Errorf("InternalPort should be 8065 (Mattermost default), got %d", InternalPort)
	}
}

func TestPermissionsAreReasonable(t *testing.T) {
	// Install dir should be 0755 (standard service dir)
	if InstallDirPerm != shared.ServiceDirPerm {
		t.Errorf("InstallDirPerm (%o) != shared.ServiceDirPerm (%o)",
			InstallDirPerm, shared.ServiceDirPerm)
	}

	// Env file should be restrictive (contains secrets)
	if EnvFilePerm != shared.SecureConfigFilePerm {
		t.Errorf("EnvFilePerm (%o) != shared.SecureConfigFilePerm (%o)",
			EnvFilePerm, shared.SecureConfigFilePerm)
	}
}
