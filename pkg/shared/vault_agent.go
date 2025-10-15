// pkg/shared/vault_agent.go

package shared

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"text/template"
	"time"

	"go.uber.org/zap"
)

const MaxWait = 30 * time.Second
const Interval = 500 * time.Millisecond

var (
	AgentToken         = filepath.Join(EosRunDir, "vault_agent_eos.token")
	AgentPID           = filepath.Join(EosRunDir, "vault_agent.pid")
	VaultAgentPassPath = filepath.Join(EosRunDir, "vault_agent.pass")
)

// Vault Agent configuration template used to render agent config file at runtime.
const AgentConfigTmpl = `
vault {
  address = "{{ .Addr }}"
  {{- if .CACert }}
  tls_ca_file = "{{ .CACert }}"
  {{- end }}
}

{{- if .EnableCache }}
listener "tcp" {
  address = "{{ .ListenerAddr }}"
}

cache {
  use_auto_auth_token = true
}
{{- end }}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = "{{ .RoleFile }}"
      secret_id_file_path = "{{ .SecretFile }}"
      remove_secret_id_file_after_reading = false
    }
  }
  sink "{{ .SinkType }}" { 
  	config = { 
	  path = "{{ .SinkPath }}" 
	  mode = 0600
	} 
  }
}
`

type AgentConfigData struct {
	Addr, CACert, ListenerAddr string
	RoleFile, SecretFile       string
	SinkType, SinkPath         string
	EnableCache                bool
}

// AgentSystemDUnit is the systemd unit template for running Vault Agent under eos.
const AgentSystemDUnit = `[Unit]
Description={{ .Description }}
After=network.target
After=systemd-tmpfiles-setup.service
After=vault.service
Requires=vault.service
StartLimitIntervalSec=30

[Service]
User={{ .User }}
Group={{ .Group }}
RuntimeDirectory={{ .RuntimeDir }}
RuntimeDirectoryMode={{ .RuntimeMode }}
RuntimeDirectoryPreserve=yes
Environment=VAULT_SKIP_HCP=true
Environment=VAULT_SKIP_TLS_VERIFY=false
ExecStartPre=/bin/mkdir -p /run/eos
ExecStartPre=/bin/chown {{ .User }}:{{ .Group }} /run/eos
ExecStart={{ .ExecStart }}
Restart=on-failure
RestartSec=5
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
`

type AgentSystemdData struct {
	Description, User, Group, RuntimeDir, RuntimePath, ExecStart, RuntimeMode string
}

// Vault Agent service + config paths
const (
	VaultAgentService      = "vault-agent-eos.service"
	VaultAgentConfigPath   = "/etc/vault-agent-eos.hcl"
	VaultAgentCACopyPath   = "/etc/vault.d/ca.crt"
	VaultSystemCATrustPath = "/etc/pki/ca-trust/source/anchors/vault-local-ca.crt"
	VaultAgentServicePath  = "/etc/systemd/system/vault-agent-eos.service"
)

func EnsureSecretsDir() error {
	log := zap.L()
	dir := filepath.Dir(AppRolePaths.RoleID) // /var/lib/eos/secret
	parentDir := filepath.Dir(dir)            // /var/lib/eos

	log.Info(" [ASSESS] Starting secrets directory setup",
		zap.String("secrets_dir", dir),
		zap.String("parent_dir", parentDir))

	// Check if parent directory already exists
	if stat, err := os.Stat(parentDir); err == nil {
		log.Debug("Parent directory already exists",
			zap.String("parent_dir", parentDir),
			zap.String("mode", stat.Mode().String()),
			zap.Bool("is_dir", stat.IsDir()))
	} else if os.IsNotExist(err) {
		log.Info(" [INTERVENE] Parent directory does not exist, will create",
			zap.String("parent_dir", parentDir))
	}

	// Ensure parent directory exists and is traversable by vault user
	log.Debug("Creating parent directory if needed",
		zap.String("parent_dir", parentDir),
		zap.String("initial_mode", "0755"))

	if err := os.MkdirAll(parentDir, 0755); err != nil {
		log.Error("Failed to create parent directory",
			zap.String("parent_dir", parentDir),
			zap.Error(err))
		return fmt.Errorf("create parent directory: %w", err)
	}

	log.Debug("Parent directory exists",
		zap.String("parent_dir", parentDir))

	// Make parent directory world-traversable so vault user can access subdirectories
	// This is safe because the actual secrets directory (/var/lib/eos/secret) will be 0700
	log.Info(" [INTERVENE] Setting parent directory permissions for vault user traversal",
		zap.String("parent_dir", parentDir),
		zap.String("target_mode", "0751"),
		zap.String("reason", "allow vault user to traverse to subdirectories"))

	if err := os.Chmod(parentDir, 0751); err != nil {
		log.Warn("Failed to set parent directory permissions - vault user may not be able to access secrets",
			zap.String("parent_dir", parentDir),
			zap.String("attempted_mode", "0751"),
			zap.Error(err))
		// Don't fail here - continue trying to set up the secrets directory
	} else {
		log.Debug("Parent directory permissions set successfully",
			zap.String("parent_dir", parentDir),
			zap.String("mode", "0751"))
	}

	// Verify parent directory final state
	if stat, err := os.Stat(parentDir); err == nil {
		log.Debug("Parent directory final state",
			zap.String("parent_dir", parentDir),
			zap.String("mode", stat.Mode().String()))
	}

	// Check if secrets directory already exists
	if stat, err := os.Stat(dir); err == nil {
		log.Debug("Secrets directory already exists",
			zap.String("secrets_dir", dir),
			zap.String("mode", stat.Mode().String()),
			zap.Bool("is_dir", stat.IsDir()))
	} else if os.IsNotExist(err) {
		log.Info(" [INTERVENE] Secrets directory does not exist, will create",
			zap.String("secrets_dir", dir))
	}

	// Create secrets directory with appropriate permissions
	log.Debug("Creating secrets directory if needed",
		zap.String("secrets_dir", dir),
		zap.String("initial_mode", "0755"))

	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Error("Failed to create secrets directory",
			zap.String("secrets_dir", dir),
			zap.Error(err))
		return fmt.Errorf("create secrets directory: %w", err)
	}

	log.Debug("Secrets directory exists",
		zap.String("secrets_dir", dir))

	// Set ownership to vault:vault
	log.Debug("Looking up vault user for ownership",
		zap.String("username", "vault"))

	vaultUser, err := user.Lookup("vault")
	if err != nil {
		log.Error("Failed to lookup vault user",
			zap.String("username", "vault"),
			zap.Error(err))
		return fmt.Errorf("lookup vault user: %w", err)
	}

	log.Debug("Vault user found",
		zap.String("username", vaultUser.Username),
		zap.String("uid", vaultUser.Uid),
		zap.String("gid", vaultUser.Gid),
		zap.String("home", vaultUser.HomeDir))

	uid, err := strconv.Atoi(vaultUser.Uid)
	if err != nil {
		log.Error("Failed to parse vault UID",
			zap.String("uid_string", vaultUser.Uid),
			zap.Error(err))
		return fmt.Errorf("parse vault UID: %w", err)
	}

	gid, err := strconv.Atoi(vaultUser.Gid)
	if err != nil {
		log.Error("Failed to parse vault GID",
			zap.String("gid_string", vaultUser.Gid),
			zap.Error(err))
		return fmt.Errorf("parse vault GID: %w", err)
	}

	log.Info(" [INTERVENE] Setting secrets directory ownership",
		zap.String("secrets_dir", dir),
		zap.String("owner", "vault"),
		zap.Int("uid", uid),
		zap.Int("gid", gid))

	if err := os.Chown(dir, uid, gid); err != nil {
		log.Error("Failed to set ownership on secrets directory",
			zap.String("secrets_dir", dir),
			zap.Int("uid", uid),
			zap.Int("gid", gid),
			zap.Error(err))
		return fmt.Errorf("set ownership on %s: %w", dir, err)
	}

	log.Debug("Ownership set successfully",
		zap.String("secrets_dir", dir),
		zap.String("owner", "vault:vault"))

	// Set restrictive permissions (only vault user can read/write/execute)
	log.Info(" [INTERVENE] Setting secrets directory permissions",
		zap.String("secrets_dir", dir),
		zap.String("target_mode", "0700"),
		zap.String("reason", "restrict access to vault user only"))

	if err := os.Chmod(dir, 0700); err != nil {
		log.Error("Failed to set permissions on secrets directory",
			zap.String("secrets_dir", dir),
			zap.String("attempted_mode", "0700"),
			zap.Error(err))
		return fmt.Errorf("set permissions on %s: %w", dir, err)
	}

	log.Debug("Permissions set successfully",
		zap.String("secrets_dir", dir),
		zap.String("mode", "0700"))

	// Verify final state
	if stat, err := os.Stat(dir); err == nil {
		log.Debug("Secrets directory final state",
			zap.String("secrets_dir", dir),
			zap.String("mode", stat.Mode().String()))
	}

	log.Info(" [EVALUATE] Secrets directory setup complete",
		zap.String("parent_dir", parentDir),
		zap.String("parent_perms", "0751"),
		zap.String("secrets_dir", dir),
		zap.String("owner", "vault:vault"),
		zap.String("permissions", "0700"))

	return nil
}

// SetFilePermission safely updates the file permissions.
func SetFilePermission(path string, perm os.FileMode) error {
	if err := os.Chmod(path, perm); err != nil {
		zap.L().Warn("Failed to set file permissions", zap.String("path", path), zap.Error(err))
		return err
	}
	zap.L().Info(" File permissions set", zap.String("path", path), zap.String("perm", fmt.Sprintf("%#o", perm)))
	return nil
}

// WriteAgentConfig renders and writes the Vault Agent HCL config from template.
func WriteAgentConfig(path string, tpl *template.Template, data any) error {
	log := zap.L()

	log.Info(" [INTERVENE] Writing Vault Agent HCL configuration",
		zap.String("config_path", path),
		zap.String("template_name", tpl.Name()))

	// Check if file already exists
	if stat, err := os.Stat(path); err == nil {
		log.Debug("Config file already exists, will overwrite",
			zap.String("path", path),
			zap.String("existing_mode", stat.Mode().String()),
			zap.Int64("existing_size", stat.Size()))
	}

	log.Debug("Creating agent config file",
		zap.String("path", path))

	f, err := os.Create(path)
	if err != nil {
		log.Error("Failed to create agent config file",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Warn("Failed to close agent config file",
				zap.String("path", path),
				zap.Error(cerr))
		}
	}()

	log.Debug("Rendering template to config file",
		zap.String("template_name", tpl.Name()))

	if err := tpl.Execute(f, data); err != nil {
		log.Error("Failed to render agent config template",
			zap.String("template_name", tpl.Name()),
			zap.Error(err))
		return fmt.Errorf("execute template: %w", err)
	}

	// Verify file was written
	if stat, err := os.Stat(path); err == nil {
		log.Info(" [EVALUATE] Vault Agent config written successfully",
			zap.String("path", path),
			zap.String("mode", stat.Mode().String()),
			zap.Int64("size", stat.Size()))
	} else {
		log.Warn("Config file written but verification stat failed",
			zap.String("path", path),
			zap.Error(err))
	}

	return nil
}

// EnsureFileExists writes value if file is missing.
// NOTE: This function does NOT set ownership. Callers should use eos_unix.WriteFile
// or eos_unix.EnsureOwnership if ownership needs to be set.
func EnsureFileExists(ctx context.Context, path, value string, perm os.FileMode) error {
	log := zap.L()

	stat, err := os.Stat(path)
	if err == nil {
		log.Info("File already exists",
			zap.String("path", path),
			zap.String("mode", stat.Mode().String()),
			zap.Int64("size", stat.Size()))
		return nil
	}

	if !os.IsNotExist(err) {
		log.Error("Failed to stat file",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("stat %s: %w", path, err)
	}

	log.Info("File missing, creating",
		zap.String("path", path),
		zap.String("permissions", fmt.Sprintf("%#o", perm)),
		zap.Int("value_length", len(value)))

	if err := os.WriteFile(path, []byte(value), perm); err != nil {
		log.Error("Failed to write file",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("write %s: %w", path, err)
	}

	// Verify final state
	stat, err = os.Stat(path)
	if err != nil {
		log.Warn("File written but verification stat failed",
			zap.String("path", path),
			zap.Error(err))
	} else {
		log.Info("File created successfully",
			zap.String("path", path),
			zap.String("mode", stat.Mode().String()),
			zap.Int64("size", stat.Size()))
	}

	return nil
}

func BuildAgentTemplateData(addr string) AgentConfigData {
	return AgentConfigData{
		Addr:         addr,
		CACert:       VaultAgentCACopyPath,
		RoleFile:     AppRolePaths.RoleID,
		SecretFile:   AppRolePaths.SecretID,
		SinkType:     "file",           // set explicitly
		SinkPath:     AgentToken,       // fix: use AgentToken, not undefined VaultAgentTokenPath
		ListenerAddr: "127.0.0.1:8180", // fix: use different port from Vault server (8179)
		EnableCache:  false,            // fix: disable cache to avoid listener requirement
	}
}

// WriteRawConfig writes raw string content to a file.
func WriteRawConfig(ctx context.Context, path, content string, perm os.FileMode) error {
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		zap.L().Error(" Failed to write config file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("write %s: %w", path, err)
	}
	zap.L().Info(" Config file written", zap.String("path", path))
	return nil
}
