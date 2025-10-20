// pkg/vault/phase13_write_agent_config.go

package vault

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	// parse once at init
	agentHCLTpl     = template.Must(template.New("agent.hcl").Parse(shared.AgentConfigTmpl))
	agentServiceTpl = template.Must(template.New("vault-agent-eos.service").Parse(shared.AgentSystemDUnit))
)

func PhaseRenderVaultAgentConfig(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)

	addr := os.Getenv(shared.VaultAddrEnv)
	if addr == "" {
		return fmt.Errorf("VAULT_ADDR not set")
	}

	// 0) create systemd tmpfiles configuration for runtime directory persistence
	if err := createTmpfilesConfig(rc); err != nil {
		return fmt.Errorf("create tmpfiles config: %w", err)
	}

	// 1) prepare /run/eos and the sink file
	// Use vault user instead of deprecated eos user
	if err := prepareTokenSink(rc, shared.AgentToken, "vault"); err != nil {
		return fmt.Errorf("prepare token sink: %w", err)
	}

	// 1.5) clean up any stale HCP directory that may cause JSON parsing issues
	if err := cleanupStaleHCPDirectory(rc); err != nil {
		log.Warn("Failed to clean stale HCP directory", zap.Error(err))
		// Don't fail the entire process as this is not critical
	}

	// 2) render + write HCL
	log.Info("Reading AppRole credentials from disk for agent configuration")

	// Pre-read diagnostics: verify credential files exist and are readable
	for _, credPath := range []struct {
		path string
		name string
	}{
		{shared.AppRolePaths.RoleID, "role_id"},
		{shared.AppRolePaths.SecretID, "secret_id"},
	} {
		if stat, err := os.Stat(credPath.path); err != nil {
			log.Error("Credential file missing or inaccessible before read",
				zap.String("file", credPath.name),
				zap.String("path", credPath.path),
				zap.Error(err))
			return fmt.Errorf("credential file %s not found at %s: %w", credPath.name, credPath.path, err)
		} else {
			log.Debug("Credential file exists and is accessible",
				zap.String("file", credPath.name),
				zap.String("path", credPath.path),
				zap.String("mode", stat.Mode().String()),
				zap.Int64("size", stat.Size()))
		}
	}

	roleID, secretID, err := readAppRoleCredsFromDisk(rc, client)
	if err != nil {
		return fmt.Errorf("read AppRole creds: %w", err)
	}

	log.Info("AppRole credentials read successfully from disk",
		zap.Int("role_id_length", len(roleID)),
		zap.Int("secret_id_length", len(secretID)))

	// 2.5) Copy Vault TLS certificate for agent to trust
	// CRITICAL: Agent WILL fail TLS verification without this
	if err := copyVaultCertForAgent(rc); err != nil {
		log.Error("Failed to copy Vault CA cert for agent - cannot proceed",
			zap.Error(err),
			zap.String("remediation", "Check that Vault TLS cert exists and is readable"))
		return fmt.Errorf("copy vault CA cert for agent: %w", err)
	}

	// VERIFY: Cert was actually copied and is readable by vault user
	if err := verifyCertCopyForAgent(rc); err != nil {
		log.Error("Vault CA cert verification failed - agent will fail TLS",
			zap.Error(err))
		return fmt.Errorf("verify vault CA cert for agent: %w", err)
	}

	if err := writeAgentHCL(rc, addr, roleID, secretID); err != nil {
		return fmt.Errorf("write agent HCL: %w", err)
	}

	// 3) render + write systemd unit (remove any stale file first)
	if err := os.Remove(shared.VaultAgentServicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cleanup old unit file: %w", err)
	}
	if err := writeAgentUnit(); err != nil {
		return fmt.Errorf("write systemd unit: %w", err)
	}

	// 4) reload & enable
	if err := eos_unix.ReloadDaemonAndEnable(rc.Ctx, shared.VaultAgentService); err != nil {
		return fmt.Errorf("reload/enable service: %w", err)
	}

	log.Info(" Vault Agent config + service installed")
	return nil
}

// prepareTokenSink ensures the runtime directory exists, ownership is correct,
// and the sink file is a fresh, zero‐length file owned by `user`.
func prepareTokenSink(rc *eos_io.RuntimeContext, tokenPath, user string) error {
	log := otelzap.Ctx(rc.Ctx)
	runDir := filepath.Dir(tokenPath)

	log.Info("Preparing Vault Agent token sink",
		zap.String("token_path", tokenPath),
		zap.String("runtime_dir", runDir),
		zap.String("target_owner", user),
		zap.String("target_permissions", "0600"))

	// Create runtime directory
	log.Debug("Creating runtime directory if needed",
		zap.String("dir", runDir),
		zap.String("mode", "0755"))

	if err := os.MkdirAll(runDir, 0o755); err != nil {
		log.Error("Failed to create runtime directory",
			zap.String("dir", runDir),
			zap.Error(err))
		return err
	}

	// Lookup target user
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, user)
	if err != nil {
		log.Error("Failed to lookup user for runtime directory ownership",
			zap.String("user", user),
			zap.Error(err))
		return err
	}

	log.Debug("User resolved for runtime directory ownership",
		zap.String("user", user),
		zap.Int("uid", uid),
		zap.Int("gid", gid))

	// Set directory ownership
	log.Debug("Setting runtime directory ownership",
		zap.String("dir", runDir),
		zap.String("user", user),
		zap.Int("uid", uid),
		zap.Int("gid", gid))

	if err := os.Chown(runDir, uid, gid); err != nil {
		log.Error("Failed to set ownership on runtime directory",
			zap.String("dir", runDir),
			zap.String("user", user),
			zap.Int("uid", uid),
			zap.Int("gid", gid),
			zap.Error(err))
		return err
	}

	// Verify directory ownership
	dirStat, err := os.Stat(runDir)
	if err != nil {
		log.Warn("Directory created but verification stat failed",
			zap.String("dir", runDir),
			zap.Error(err))
	} else {
		log.Debug("Runtime directory ownership verified",
			zap.String("dir", runDir),
			zap.String("mode", dirStat.Mode().String()),
			zap.String("owner", user))
	}

	// Remove stray directory if token path is a directory
	if fi, err := os.Lstat(tokenPath); err == nil && fi.IsDir() {
		log.Warn("Token path exists as directory, removing",
			zap.String("path", tokenPath))
		if err := os.RemoveAll(tokenPath); err != nil {
			log.Error("Failed to remove stray directory at token path",
				zap.String("path", tokenPath),
				zap.Error(err))
			return err
		}
		log.Debug("Stray directory removed", zap.String("path", tokenPath))
	}

	// Create empty token file
	log.Debug("Creating empty token sink file",
		zap.String("path", tokenPath),
		zap.String("mode", "0600"))

	f, err := os.OpenFile(tokenPath,
		os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		log.Error("Failed to create token sink file",
			zap.String("path", tokenPath),
			zap.Error(err))
		return err
	}
	if cerr := f.Close(); cerr != nil {
		log.Error("Failed to close token sink file after creation",
			zap.String("path", tokenPath),
			zap.Error(cerr))
		return cerr
	}

	// Set token file ownership
	log.Debug("Setting token file ownership",
		zap.String("path", tokenPath),
		zap.String("user", user),
		zap.Int("uid", uid),
		zap.Int("gid", gid))

	if err := os.Chown(tokenPath, uid, gid); err != nil {
		log.Error("Failed to set ownership on token file",
			zap.String("path", tokenPath),
			zap.String("user", user),
			zap.Int("uid", uid),
			zap.Int("gid", gid),
			zap.Error(err))
		return err
	}

	// Final verification of token file
	tokenStat, err := os.Stat(tokenPath)
	if err != nil {
		log.Warn("Token file created but verification stat failed",
			zap.String("path", tokenPath),
			zap.Error(err))
	} else {
		log.Info("Token sink prepared successfully",
			zap.String("path", tokenPath),
			zap.String("mode", tokenStat.Mode().String()),
			zap.Int64("size", tokenStat.Size()),
			zap.String("owner", user))
	}

	return nil
}

func writeAgentHCL(rc *eos_io.RuntimeContext, addr, _roleID, _secretID string) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Writing Vault Agent HCL configuration",
		zap.String("config_path", shared.VaultAgentConfigPath),
		zap.String("vault_addr", addr),
		zap.String("role_id_path", shared.AppRolePaths.RoleID),
		zap.String("secret_id_path", shared.AppRolePaths.SecretID),
		zap.String("target_owner", "vault"))

	// NOTE: AppRole credential files should already exist from Phase 10b.
	// We do NOT write them here to avoid race conditions and redundancy.
	// Phase 10b is responsible for: 1) Creating AppRole in Vault, 2) Writing credential files
	// Phase 13 is responsible for: 1) Reading credential files, 2) Writing agent HCL config

	log.Debug("Using AppRole credentials from Phase 10b",
		zap.String("role_id_file", shared.AppRolePaths.RoleID),
		zap.String("secret_id_file", shared.AppRolePaths.SecretID))

	// Build template data
	data := shared.BuildAgentTemplateData(addr)
	path := shared.VaultAgentConfigPath

	log.Info("Rendering Vault Agent config file",
		zap.String("path", path),
		zap.String("vault_addr", data.Addr),
		zap.String("sink_path", data.SinkPath),
		zap.String("target_owner", "vault"))

	// Render template to memory first
	var buf bytes.Buffer
	if err := agentHCLTpl.Execute(&buf, data); err != nil {
		log.Error("Failed to render Vault Agent config template",
			zap.Error(err))
		return fmt.Errorf("render template: %w", err)
	}

	renderedConfig := buf.String()

	log.Debug("Template rendered successfully",
		zap.Int("size_bytes", buf.Len()))

	// DIAGNOSTIC: Log the rendered config content for debugging
	log.Info("[DIAGNOSTIC] Rendered Vault Agent HCL configuration:",
		zap.String("content", renderedConfig))

	// Verify TLS configuration is present (either tls_ca_file or tls_skip_verify)
	hasTLSCaFile := bytes.Contains(buf.Bytes(), []byte("tls_ca_file"))
	hasTLSSkipVerify := bytes.Contains(buf.Bytes(), []byte("tls_skip_verify"))

	if !hasTLSCaFile && !hasTLSSkipVerify {
		log.Error("Agent config missing TLS configuration!",
			zap.String("expected", "either tls_ca_file or tls_skip_verify"),
			zap.String("ca_cert_path", data.CACert),
			zap.Bool("tls_skip_verify", data.TLSSkipVerify))
		return fmt.Errorf("rendered agent config missing TLS configuration (neither tls_ca_file nor tls_skip_verify present)")
	}

	if hasTLSSkipVerify {
		log.Info("TLS skip verify enabled in agent config (development mode)",
			zap.Bool("tls_skip_verify", true),
			zap.String("reason", "Self-signed certificate with hostname/SAN mismatch"))
	} else if hasTLSCaFile {
		log.Debug("TLS CA file reference verified in rendered config",
			zap.String("ca_cert", data.CACert))
	}

	// Write config file with vault ownership using eos_unix.WriteFile
	log.Debug("Writing config file with vault ownership",
		zap.String("path", path),
		zap.String("mode", fmt.Sprintf("%#o", shared.RuntimeFilePerms)))

	if err := eos_unix.WriteFile(rc.Ctx, path, buf.Bytes(), shared.RuntimeFilePerms, "vault"); err != nil {
		log.Error("Failed to write Vault Agent config file with ownership",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("write config file: %w", err)
	}

	// Final verification
	stat, err := os.Stat(path)
	if err != nil {
		log.Warn("Config file written but verification stat failed",
			zap.String("path", path),
			zap.Error(err))
	} else {
		log.Info("Vault Agent HCL configuration written successfully",
			zap.String("path", path),
			zap.String("mode", stat.Mode().String()),
			zap.Int64("size", stat.Size()),
			zap.String("owner", "vault"))
	}

	return nil
}

func writeAgentUnit() error {
	log := otelzap.L()

	data := shared.AgentSystemdData{
		Description: "Vault Agent (Eos)",
		User:        "vault",
		Group:       "vault",
		RuntimeDir:  "eos", // fix: use relative path for RuntimeDirectory, not absolute
		ExecStart:   fmt.Sprintf("vault agent -config=%s", shared.VaultAgentConfigPath),
		RuntimeMode: "0700",
	}

	path := shared.VaultAgentServicePath

	log.Info("Writing Vault Agent systemd unit file",
		zap.String("path", path),
		zap.String("user", data.User),
		zap.String("group", data.Group),
		zap.String("runtime_dir", data.RuntimeDir),
		zap.String("exec_start", data.ExecStart))

	log.Debug("Creating systemd unit file",
		zap.String("path", path))

	f, err := os.Create(path)
	if err != nil {
		log.Error("Failed to create systemd unit file",
			zap.String("path", path),
			zap.Error(err))
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Warn("Failed to close systemd unit file",
				zap.String("path", path),
				zap.Error(cerr))
		}
	}()

	log.Debug("Rendering systemd unit template")

	if err := agentServiceTpl.Execute(f, data); err != nil {
		log.Error("Failed to render systemd unit template",
			zap.Error(err))
		return err
	}

	log.Debug("Setting systemd unit file permissions",
		zap.String("path", path),
		zap.String("mode", "0644"))

	if err := os.Chmod(path, 0o644); err != nil {
		log.Error("Failed to set systemd unit file permissions",
			zap.String("path", path),
			zap.Error(err))
		return err
	}

	// Verify final state
	stat, err := os.Stat(path)
	if err != nil {
		log.Warn("Systemd unit file written but verification stat failed",
			zap.String("path", path),
			zap.Error(err))
	} else {
		log.Info("Vault Agent systemd unit file written successfully",
			zap.String("path", path),
			zap.String("mode", stat.Mode().String()),
			zap.Int64("size", stat.Size()))
	}

	return nil
}

// copyVaultCertForAgent copies the Vault TLS certificate to where the agent expects it
func copyVaultCertForAgent(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	srcCert := shared.TLSCrt // /etc/vault.d/tls/vault.crt
	dstCert := shared.VaultAgentCACopyPath // /etc/vault.d/ca.crt

	log.Info("Copying Vault TLS certificate for agent trust",
		zap.String("src", srcCert),
		zap.String("dst", dstCert))

	// Check if source cert exists
	if _, err := os.Stat(srcCert); err != nil {
		log.Error("Source Vault certificate not found",
			zap.String("src", srcCert),
			zap.Error(err))
		return fmt.Errorf("source certificate not found at %s: %w", srcCert, err)
	}

	log.Debug("Source certificate exists",
		zap.String("src", srcCert))

	// Copy the certificate
	if err := eos_unix.CopyFile(rc.Ctx, srcCert, dstCert, 0644); err != nil {
		log.Error("Failed to copy certificate",
			zap.String("src", srcCert),
			zap.String("dst", dstCert),
			zap.Error(err))
		return fmt.Errorf("copy certificate: %w", err)
	}

	log.Debug("Certificate copied successfully",
		zap.String("dst", dstCert))

	// Set ownership to vault user
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "vault")
	if err != nil {
		log.Error("Failed to lookup vault user for cert ownership",
			zap.Error(err))
		return fmt.Errorf("lookup vault user: %w", err)
	}

	log.Debug("Setting certificate ownership",
		zap.String("path", dstCert),
		zap.String("owner", "vault"),
		zap.Int("uid", uid),
		zap.Int("gid", gid))

	if err := os.Chown(dstCert, uid, gid); err != nil {
		log.Error("Failed to set certificate ownership",
			zap.String("dst", dstCert),
			zap.Int("uid", uid),
			zap.Int("gid", gid),
			zap.Error(err))
		return fmt.Errorf("chown certificate: %w", err)
	}

	// Verify final state
	stat, err := os.Stat(dstCert)
	if err != nil {
		log.Error("Certificate stat failed after copy",
			zap.String("path", dstCert),
			zap.Error(err))
		return fmt.Errorf("stat certificate after copy: %w", err)
	}

	log.Info("[INTERVENE] Vault CA certificate copied for agent",
		zap.String("path", dstCert),
		zap.String("mode", stat.Mode().String()),
		zap.Int64("size", stat.Size()))

	return nil
}

// verifyCertCopyForAgent verifies that the CA certificate was copied correctly and is readable by vault user
func verifyCertCopyForAgent(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	dstCert := shared.VaultAgentCACopyPath // /etc/vault.d/ca.crt

	log.Info("[ASSESS] Verifying CA certificate is readable by vault user",
		zap.String("path", dstCert))

	// 1. Check file exists
	stat, err := os.Stat(dstCert)
	if err != nil {
		log.Error("CA certificate file not found after copy",
			zap.String("path", dstCert),
			zap.Error(err))
		return fmt.Errorf("CA cert not found at %s: %w", dstCert, err)
	}

	log.Debug("CA certificate exists",
		zap.String("path", dstCert),
		zap.String("mode", stat.Mode().String()),
		zap.Int64("size", stat.Size()))

	// 2. Check file is not empty
	if stat.Size() == 0 {
		log.Error("CA certificate file is empty",
			zap.String("path", dstCert))
		return fmt.Errorf("CA cert at %s is empty", dstCert)
	}

	// 3. Verify vault user can read it
	log.Debug("Testing vault user read access",
		zap.String("path", dstCert))

	testCmd := exec.Command("sudo", "-u", "vault", "test", "-r", dstCert)
	if err := testCmd.Run(); err != nil {
		log.Error("Vault user cannot read CA certificate",
			zap.String("path", dstCert),
			zap.Error(err),
			zap.String("remediation", "Check file permissions and ownership"))
		return fmt.Errorf("vault user cannot read CA cert at %s: %w", dstCert, err)
	}

	log.Info("[EVALUATE] CA certificate verified - vault user can read it",
		zap.String("path", dstCert),
		zap.Int64("size", stat.Size()),
		zap.String("mode", stat.Mode().String()))

	return nil
}

// createTmpfilesConfig creates systemd tmpfiles configuration to ensure /run/eos persists across reboots
func createTmpfilesConfig(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	tmpfilesPath := "/etc/tmpfiles.d/eos.conf"
	// Use vault user instead of deprecated eos user
	tmpfilesContent := fmt.Sprintf("d %s 0755 vault vault -\n", shared.EosRunDir)

	log.Info(" Creating systemd tmpfiles configuration", zap.String("path", tmpfilesPath))

	if err := os.WriteFile(tmpfilesPath, []byte(tmpfilesContent), shared.FilePermStandard); err != nil {
		return fmt.Errorf("write tmpfiles config %s: %w", tmpfilesPath, err)
	}

	// Apply tmpfiles configuration immediately to create runtime directory
	log.Info(" Applying tmpfiles configuration immediately")
	cmd := exec.CommandContext(rc.Ctx, "systemd-tmpfiles", "--create", fmt.Sprintf("--prefix=%s", shared.EosRunDir))
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Error(" Failed to apply tmpfiles config immediately",
			zap.Error(err),
			zap.String("output", string(out)))
		// This is critical for Vault Agent to work, so return the error
		return fmt.Errorf("failed to apply tmpfiles config: %w", err)
	}

	// Verify the directory was created
	if stat, err := os.Stat("/run/eos"); err != nil {
		log.Error(" /run/eos directory still doesn't exist after tmpfiles creation", zap.Error(err))
		return fmt.Errorf("runtime directory not created by tmpfiles: %w", err)
	} else {
		log.Info(" Runtime directory created by tmpfiles",
			zap.String("path", "/run/eos"),
			zap.String("mode", stat.Mode().String()))
	}

	log.Info(" Systemd tmpfiles configuration created and applied", zap.String("path", tmpfilesPath))
	return nil
}

// cleanupStaleHCPDirectory removes the HCP directory that vault binary creates despite VAULT_SKIP_HCP=true
func cleanupStaleHCPDirectory(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	// Use vault user's home instead of deprecated eos user
	hcpDir := "/home/vault/.config/hcp"

	// Check if directory exists
	if _, err := os.Stat(hcpDir); os.IsNotExist(err) {
		log.Info(" HCP directory does not exist - no cleanup needed")
		return nil
	}

	log.Info(" Cleaning up stale HCP directory to prevent JSON parsing issues",
		zap.String("path", hcpDir))

	// Remove the entire HCP directory
	if err := os.RemoveAll(hcpDir); err != nil {
		log.Error(" Failed to remove HCP directory",
			zap.String("path", hcpDir),
			zap.Error(err))
		return fmt.Errorf("remove HCP directory %s: %w", hcpDir, err)
	}

	log.Info(" HCP directory cleaned up successfully", zap.String("path", hcpDir))
	return nil
}
