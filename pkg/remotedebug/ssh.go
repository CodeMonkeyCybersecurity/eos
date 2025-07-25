package remotedebug

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	
	"golang.org/x/crypto/ssh"
)

// SSHClient wraps the SSH connection with helper methods
type SSHClient struct {
	client   *ssh.Client
	config   *Config
}

// NewSSHClient creates a new SSH client with standard connection strategies
func NewSSHClient(config *Config) (*SSHClient, error) {
	client, err := createSSHConnection(config, "normal")
	if err != nil {
		return nil, err
	}
	
	return &SSHClient{
		client: client,
		config: config,
	}, nil
}

// NewEmergencySSHClient tries emergency connection strategies for problematic servers
func NewEmergencySSHClient(config *Config) (*SSHClient, error) {
	strategies := []string{"no-pty", "minimal", "bare"}
	
	var lastErr error
	for _, strategy := range strategies {
		client, err := createSSHConnection(config, strategy)
		if err == nil {
			return &SSHClient{
				client: client,
				config: config,
			}, nil
		}
		lastErr = err
	}
	
	return nil, fmt.Errorf("all emergency strategies failed: %w", lastErr)
}

// createSSHConnection creates an SSH connection with the specified strategy
func createSSHConnection(config *Config, strategy string) (*ssh.Client, error) {
	// Build auth methods
	var authMethods []ssh.AuthMethod
	
	// Try SSH key first if provided
	if config.KeyPath != "" {
		key, err := os.ReadFile(config.KeyPath)
		if err == nil {
			signer, err := ssh.ParsePrivateKey(key)
			if err == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			}
		}
	}
	
	// Add password auth if provided
	if config.Password != "" {
		authMethods = append(authMethods, ssh.Password(config.Password))
	}
	
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication methods available")
	}
	
	// Create SSH client config
	clientConfig := &ssh.ClientConfig{
		User:            config.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: In production, use proper host key verification
		Timeout:         config.Timeout,
	}
	
	// Apply strategy-specific settings
	switch strategy {
	case "no-pty":
		// No special config needed, handled in command execution
	case "minimal":
		// Use minimal cipher set
		clientConfig.Config.Ciphers = []string{"aes128-ctr"}
		clientConfig.Config.MACs = []string{"hmac-sha1"}
	case "bare":
		// Most minimal settings
		clientConfig.Config.Ciphers = []string{"aes128-ctr"}
		clientConfig.Config.MACs = []string{"hmac-sha1"}
		clientConfig.Config.KeyExchanges = []string{"diffie-hellman-group14-sha1"}
	}
	
	// Connect
	addr := fmt.Sprintf("%s:%s", config.Host, config.Port)
	return ssh.Dial("tcp", addr, clientConfig)
}

// ExecuteCommand runs a command on the remote host with multiple fallback strategies
func (c *SSHClient) ExecuteCommand(cmd string, useSudo bool) (string, error) {
	// Build the actual command
	actualCmd := cmd
	if useSudo && c.config.SudoPass != "" {
		actualCmd = fmt.Sprintf("echo '%s' | sudo -S %s", c.config.SudoPass, cmd)
	} else if useSudo {
		actualCmd = fmt.Sprintf("sudo %s", cmd)
	}
	
	// Try different execution strategies
	strategies := []func() (string, error){
		// Strategy 1: Normal execution with PTY
		func() (string, error) {
			return c.executeWithPTY(actualCmd)
		},
		// Strategy 2: Non-interactive without PTY
		func() (string, error) {
			return c.executeNoPTY(actualCmd)
		},
		// Strategy 3: Wrapped in shell
		func() (string, error) {
			wrappedCmd := fmt.Sprintf("sh -c '%s'", strings.ReplaceAll(actualCmd, "'", "'\"'\"'"))
			return c.executeNoPTY(wrappedCmd)
		},
	}
	
	var lastErr error
	for _, strategy := range strategies {
		output, err := strategy()
		if err == nil {
			return output, nil
		}
		lastErr = err
	}
	
	return "", fmt.Errorf("all execution strategies failed: %w", lastErr)
}

// executeWithPTY executes a command with a pseudo-terminal
func (c *SSHClient) executeWithPTY(cmd string) (string, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()
	
	// Request PTY
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return "", fmt.Errorf("failed to request PTY: %w", err)
	}
	
	var stdout bytes.Buffer
	session.Stdout = &stdout
	
	if err := session.Run(cmd); err != nil {
		return stdout.String(), fmt.Errorf("command failed: %w", err)
	}
	
	return stdout.String(), nil
}

// executeNoPTY executes a command without a pseudo-terminal
func (c *SSHClient) executeNoPTY(cmd string) (string, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()
	
	// Don't request PTY
	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return string(output), fmt.Errorf("command failed: %w", err)
	}
	
	return string(output), nil
}

// Close closes the SSH connection
func (c *SSHClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// IsConnected checks if the SSH connection is still active
func (c *SSHClient) IsConnected() bool {
	if c.client == nil {
		return false
	}
	
	// Try to create a session as a connectivity check
	session, err := c.client.NewSession()
	if err != nil {
		return false
	}
	session.Close()
	return true
}

// GetHostInfo retrieves basic host information
func (c *SSHClient) GetHostInfo() (string, error) {
	return c.ExecuteCommand("hostname", false)
}