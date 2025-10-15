// pkg/shared/vault_agent.go

package shared

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	return os.MkdirAll(filepath.Dir(AppRolePaths.RoleID), FilePermOwnerRWX)
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
	f, err := os.Create(path)
	if err != nil {
		zap.L().Error(" Failed to create agent config file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			zap.L().Warn("Failed to close agent config file", zap.String("path", path), zap.Error(cerr))
		}
	}()

	if err := tpl.Execute(f, data); err != nil {
		zap.L().Error(" Failed to render agent config template", zap.Error(err))
		return fmt.Errorf("execute template: %w", err)
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
