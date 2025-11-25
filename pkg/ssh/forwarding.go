package ssh

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/remotedebug"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// RemoteExecutor provides the minimal interface needed for remote SSH operations.
type RemoteExecutor interface {
	ExecuteCommand(cmd string, useSudo bool) (string, error)
}

// ConnectionConfig captures how to reach a remote host for SSH operations.
type ConnectionConfig struct {
	Host         string
	User         string
	Port         string
	KeyPath      string
	Password     string
	SudoPassword string
}

// ForwardingStatus describes the forwarding-relevant parts of sshd_config and service health.
type ForwardingStatus struct {
	AllowTcpForwarding         string
	AllowStreamLocalForwarding string
	PermitOpen                 []string
	ServiceStatus              string
}

// ForwardingUpdateResult returns details from enabling forwarding.
type ForwardingUpdateResult struct {
	BackupPath       string
	RestartCommand   string
	ValidationOutput string
	Status           *ForwardingStatus
}

// ForwardingTestResult reports whether port forwarding requests are permitted.
type ForwardingTestResult struct {
	Success bool
	Message string
	Target  string
}

// BuildConnectionConfig normalizes host/user/port and applies sensible defaults.
func BuildConnectionConfig(hostArg, userOverride, portOverride, keyPath, password, sudoPassword string) (*ConnectionConfig, error) {
	hostArg = strings.TrimSpace(hostArg)
	if hostArg == "" {
		return nil, fmt.Errorf("host is required")
	}

	resolvedUser := strings.TrimSpace(userOverride)
	resolvedPort := strings.TrimSpace(portOverride)
	targetHost := hostArg

	// Allow user@host syntax
	if strings.Contains(targetHost, "@") {
		parts := strings.SplitN(targetHost, "@", 2)
		if resolvedUser == "" {
			resolvedUser = parts[0]
		}
		targetHost = parts[1]
	}

	// Allow host:port syntax
	if strings.Contains(targetHost, ":") {
		if h, p, err := net.SplitHostPort(targetHost); err == nil {
			targetHost = h
			if resolvedPort == "" {
				resolvedPort = p
			}
		}
	}

	if resolvedUser == "" {
		current, err := user.Current()
		if err == nil {
			resolvedUser = current.Username
		} else {
			resolvedUser = "root"
		}
	}

	if resolvedPort == "" {
		resolvedPort = "22"
	}

	if sudoPassword == "" {
		sudoPassword = password
	}

	if keyPath == "" {
		keyPath = detectDefaultSSHKey()
	}

	return &ConnectionConfig{
		Host:         targetHost,
		User:         resolvedUser,
		Port:         resolvedPort,
		KeyPath:      keyPath,
		Password:     password,
		SudoPassword: sudoPassword,
	}, nil
}

// ConnectSSHClient establishes an SSH client using the remotedebug transport helpers.
func ConnectSSHClient(rc *eos_io.RuntimeContext, cfg *ConnectionConfig) (*remotedebug.SSHClient, error) {
	logger := otelzap.Ctx(rc.Ctx)

	clientCfg := &remotedebug.Config{
		Host:     cfg.Host,
		Port:     cfg.Port,
		User:     cfg.User,
		Password: cfg.Password,
		KeyPath:  cfg.KeyPath,
		SudoPass: cfg.SudoPassword,
		Timeout:  remotedebug.DefaultSSHTimeout,
	}

	client, err := remotedebug.NewSSHClient(clientCfg)
	if err != nil {
		logger.Warn("Primary SSH connection failed, trying emergency strategies",
			zap.String("host", cfg.Host),
			zap.Error(err))
		client, err = remotedebug.NewEmergencySSHClient(clientCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to %s: %w", cfg.Host, err)
		}
	}

	return client, nil
}

// ReadForwardingStatus inspects sshd_config for forwarding directives and service health.
func ReadForwardingStatus(rc *eos_io.RuntimeContext, exec RemoteExecutor) (*ForwardingStatus, error) {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.ReadForwardingStatus")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	status := &ForwardingStatus{}

	allowTCP, err := fetchDirective(exec, "AllowTcpForwarding")
	if err != nil {
		logger.Warn("Failed to read AllowTcpForwarding", zap.Error(err))
	}
	if allowTCP == "" {
		allowTCP = "default (yes)"
	}
	status.AllowTcpForwarding = allowTCP

	allowStream, err := fetchDirective(exec, "AllowStreamLocalForwarding")
	if err != nil {
		logger.Warn("Failed to read AllowStreamLocalForwarding", zap.Error(err))
	}
	if allowStream == "" {
		allowStream = "default (yes)"
	}
	status.AllowStreamLocalForwarding = allowStream

	permitOpen, err := fetchPermitOpen(exec)
	if err != nil {
		logger.Warn("Failed to read PermitOpen directives", zap.Error(err))
	}
	status.PermitOpen = permitOpen

	serviceStatus, err := exec.ExecuteCommand("systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || echo unknown", true)
	if err != nil {
		logger.Warn("Failed to read SSH service status", zap.Error(err))
	}
	status.ServiceStatus = strings.TrimSpace(serviceStatus)

	return status, nil
}

// EnableSSHForwarding enforces forwarding-friendly settings and restarts sshd.
func EnableSSHForwarding(rc *eos_io.RuntimeContext, exec RemoteExecutor) (*ForwardingUpdateResult, error) {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.EnableSSHForwarding")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	backupPath := fmt.Sprintf("/etc/ssh/sshd_config.eos.bak.%s", time.Now().Format("20060102-150405"))

	if _, err := exec.ExecuteCommand(fmt.Sprintf("cp /etc/ssh/sshd_config %s", backupPath), true); err != nil {
		return nil, fmt.Errorf("failed to back up sshd_config: %w", err)
	}

	updateCommands := []string{
		`if grep -qi '^\s*AllowTcpForwarding' /etc/ssh/sshd_config; then sed -i 's/^#*\s*AllowTcpForwarding.*/AllowTcpForwarding yes/' /etc/ssh/sshd_config; else echo 'AllowTcpForwarding yes' >> /etc/ssh/sshd_config; fi`,
		`if grep -qi '^\s*AllowStreamLocalForwarding' /etc/ssh/sshd_config; then sed -i 's/^#*\s*AllowStreamLocalForwarding.*/AllowStreamLocalForwarding yes/' /etc/ssh/sshd_config; else echo 'AllowStreamLocalForwarding yes' >> /etc/ssh/sshd_config; fi`,
		`sed -i '/^\s*PermitOpen/d' /etc/ssh/sshd_config`,
	}

	for _, cmd := range updateCommands {
		if _, err := exec.ExecuteCommand(cmd, true); err != nil {
			return nil, fmt.Errorf("failed to apply sshd_config changes: %w", err)
		}
	}

	validationOutput, err := exec.ExecuteCommand("sshd -t", true)
	if err != nil {
		return nil, fmt.Errorf("sshd -t failed: %w; output: %s", err, strings.TrimSpace(validationOutput))
	}

	restartCmd, err := restartSSHServiceRemote(exec, logger)
	if err != nil {
		return nil, err
	}

	status, err := ReadForwardingStatus(rc, exec)
	if err != nil {
		return nil, err
	}

	return &ForwardingUpdateResult{
		BackupPath:       backupPath,
		RestartCommand:   restartCmd,
		ValidationOutput: strings.TrimSpace(validationOutput),
		Status:           status,
	}, nil
}

// TestForwarding attempts a forwarded TCP connection to validate forwarding permissions.
func TestForwarding(rc *eos_io.RuntimeContext, cfg *ConnectionConfig, target string) (*ForwardingTestResult, error) {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.TestForwarding")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	if target == "" {
		target = "127.0.0.1:22"
	}

	authMethods, cleanup := buildAuthMethods(cfg)
	defer cleanup()
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no SSH authentication methods available (provide --key or --password)")
	}

	clientConfig := &gossh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         20 * time.Second,
	}

	client, err := gossh.Dial("tcp", net.JoinHostPort(cfg.Host, cfg.Port), clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", cfg.Host, err)
	}
	defer func() {
		_ = client.Close()
	}()

	logger.Info("Testing forwarded connection", zap.String("target", target))
	conn, err := client.Dial("tcp", target)
	if err != nil {
		return &ForwardingTestResult{
			Success: false,
			Message: fmt.Sprintf("forwarding blocked: %v", err),
			Target:  target,
		}, nil
	}
	_ = conn.Close()

	return &ForwardingTestResult{
		Success: true,
		Message: "port forwarding allowed",
		Target:  target,
	}, nil
}

func fetchDirective(exec RemoteExecutor, directive string) (string, error) {
	cmd := fmt.Sprintf(`grep -iE '^\s*%s' /etc/ssh/sshd_config | tail -n 1 | awk '{print $2}'`, directive)
	output, err := exec.ExecuteCommand(cmd, true)
	return strings.TrimSpace(output), err
}

func fetchPermitOpen(exec RemoteExecutor) ([]string, error) {
	output, err := exec.ExecuteCommand(`grep -iE '^\s*PermitOpen' /etc/ssh/sshd_config | awk '{print $2}'`, true)
	if err != nil {
		return nil, err
	}
	lines := strings.Fields(strings.TrimSpace(output))
	return lines, nil
}

func restartSSHServiceRemote(exec RemoteExecutor, logger otelzap.LoggerWithCtx) (string, error) {
	commands := []string{
		"systemctl restart sshd",
		"systemctl restart ssh",
		"service sshd restart",
		"service ssh restart",
	}

	for _, cmd := range commands {
		if _, err := exec.ExecuteCommand(cmd, true); err == nil {
			logger.Info("Restarted SSH service", zap.String("command", cmd))
			return cmd, nil
		}
	}

	return "", fmt.Errorf("failed to restart SSH service with known commands")
}

func detectDefaultSSHKey() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	candidates := []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_rsa"),
		filepath.Join(home, ".ssh", "id_ecdsa"),
	}

	for _, key := range candidates {
		if _, err := os.Stat(key); err == nil {
			return key
		}
	}
	return ""
}

func buildAuthMethods(cfg *ConnectionConfig) ([]gossh.AuthMethod, func()) {
	var methods []gossh.AuthMethod
	var cleanupFn func()

	if cfg.KeyPath != "" {
		if keyData, err := os.ReadFile(cfg.KeyPath); err == nil {
			if signer, err := gossh.ParsePrivateKey(keyData); err == nil {
				methods = append(methods, gossh.PublicKeys(signer))
			}
		}
	}

	if cfg.Password != "" {
		methods = append(methods, gossh.Password(cfg.Password))
	}

	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			agentClient := agent.NewClient(conn)
			methods = append(methods, gossh.PublicKeysCallback(agentClient.Signers))
			cleanupFn = func() { _ = conn.Close() }
		}
	}

	if cleanupFn == nil {
		cleanupFn = func() {}
	}

	return methods, cleanupFn
}
