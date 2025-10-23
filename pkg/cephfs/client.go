//go:build !darwin
// +build !darwin

package cephfs

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/ceph/go-ceph/cephfs/admin"
	"github.com/ceph/go-ceph/rados"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CephClient provides high-level interface for Ceph operations using go-ceph SDK
type CephClient struct {
	conn          *rados.Conn
	fsAdmin       *admin.FSAdmin
	rc            *eos_io.RuntimeContext
	config        *ClientConfig
	secretManager *secrets.SecretManager
}

// ClientConfig contains configuration for Ceph client connection
type ClientConfig struct {
	// Connection settings
	ClusterName string   // Default: "ceph"
	User        string   // Default: "admin"
	ConfigFile  string   // Path to ceph.conf
	MonHosts    []string // Monitor addresses

	// Keyring management (via SecretManager)
	UseVault    bool   // Use Vault for keyring storage
	KeyringPath string // Path to keyring file (if not using Vault)

	// Timeouts
	ConnectTimeout time.Duration // Default: 30s
	OpTimeout      time.Duration // Default: 60s

	// Consul integration (optional)
	ConsulEnabled bool
	ConsulService string // Service name in Consul for monitor discovery
}

// NewCephClient creates a new Ceph client with environment discovery and secret management
func NewCephClient(rc *eos_io.RuntimeContext, config *ClientConfig) (*CephClient, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Discover environment and initialize secrets
	logger.Info("Assessing Ceph client prerequisites")

	// Discover environment
	envConfig, err := environment.DiscoverEnvironment(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to discover environment: %w", err)
	}

	// Initialize secret manager
	secretManager, err := secrets.NewSecretManager(rc, envConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize secret manager: %w", err)
	}

	// Apply defaults
	if config.ClusterName == "" {
		config.ClusterName = "ceph"
	}
	if config.User == "" {
		config.User = "admin"
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 30 * time.Second
	}
	if config.OpTimeout == 0 {
		config.OpTimeout = 60 * time.Second
	}

	// Discover Consul monitors if enabled
	if config.ConsulEnabled {
		if err := discoverConsulMonitors(rc, config); err != nil {
			logger.Warn("Failed to discover monitors from Consul, using configured monitors",
				zap.Error(err))
		}
	}

	client := &CephClient{
		rc:            rc,
		config:        config,
		secretManager: secretManager,
	}

	// INTERVENE: Establish connection
	logger.Info("Connecting to Ceph cluster",
		zap.String("cluster", config.ClusterName),
		zap.String("user", config.User),
		zap.Strings("monitors", config.MonHosts))

	if err := client.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to Ceph cluster: %w", err)
	}

	// EVALUATE: Verify connection
	logger.Info("Verifying Ceph connection")
	if err := client.verifyConnection(); err != nil {
		client.Close()
		return nil, fmt.Errorf("connection verification failed: %w", err)
	}

	logger.Info("Ceph client initialized successfully")
	return client, nil
}

// connect establishes connection to Ceph cluster using go-ceph SDK
func (c *CephClient) connect() error {
	logger := otelzap.Ctx(c.rc.Ctx)

	// Create connection
	conn, err := rados.NewConn()
	if err != nil {
		return fmt.Errorf("failed to create Ceph connection: %w", err)
	}

	// Configure connection
	if c.config.ConfigFile != "" {
		logger.Debug("Reading Ceph config file", zap.String("path", c.config.ConfigFile))
		if err := conn.ReadConfigFile(c.config.ConfigFile); err != nil {
			conn.Shutdown()
			return fmt.Errorf("failed to read config file %s: %w", c.config.ConfigFile, err)
		}
	} else {
		// Set default config
		if err := conn.ReadDefaultConfigFile(); err != nil {
			logger.Debug("No default config file found, using manual configuration")
		}
	}

	// Set monitor addresses if provided
	if len(c.config.MonHosts) > 0 {
		monString := ""
		for i, mon := range c.config.MonHosts {
			if i > 0 {
				monString += ","
			}
			monString += mon
		}
		logger.Debug("Setting monitor addresses", zap.String("mons", monString))
		if err := conn.SetConfigOption("mon_host", monString); err != nil {
			conn.Shutdown()
			return fmt.Errorf("failed to set monitor addresses: %w", err)
		}
	}

	// Retrieve keyring from SecretManager
	logger.Debug("Retrieving Ceph keyring from SecretManager")
	keyring, err := c.getKeyring()
	if err != nil {
		conn.Shutdown()
		return fmt.Errorf("failed to retrieve keyring: %w", err)
	}

	// Set keyring
	if err := conn.SetConfigOption("keyring", keyring); err != nil {
		conn.Shutdown()
		return fmt.Errorf("failed to set keyring: %w", err)
	}

	// Set client name
	if err := conn.SetConfigOption("name", fmt.Sprintf("client.%s", c.config.User)); err != nil {
		conn.Shutdown()
		return fmt.Errorf("failed to set client name: %w", err)
	}

	// Connect with timeout
	logger.Debug("Connecting to Ceph cluster with timeout",
		zap.Duration("timeout", c.config.ConnectTimeout))

	ctx, cancel := context.WithTimeout(c.rc.Ctx, c.config.ConnectTimeout)
	defer cancel()

	connectChan := make(chan error, 1)
	go func() {
		connectChan <- conn.Connect()
	}()

	select {
	case err := <-connectChan:
		if err != nil {
			conn.Shutdown()
			return fmt.Errorf("failed to connect to Ceph cluster: %w", err)
		}
	case <-ctx.Done():
		conn.Shutdown()
		return fmt.Errorf("connection timeout after %v", c.config.ConnectTimeout)
	}

	c.conn = conn

	// Initialize FSAdmin for CephFS operations
	logger.Debug("Initializing FSAdmin client")
	fsAdmin := admin.NewFromConn(conn)
	c.fsAdmin = fsAdmin

	return nil
}

// getKeyring retrieves the Ceph keyring from SecretManager
func (c *CephClient) getKeyring() (string, error) {
	logger := otelzap.Ctx(c.rc.Ctx)

	// Define required secrets for Ceph
	requiredSecrets := map[string]secrets.SecretType{
		"keyring": secrets.SecretTypeToken,
	}

	// Try to retrieve existing secrets
	serviceSecrets, err := c.secretManager.GetOrGenerateServiceSecrets("ceph", requiredSecrets)
	if err != nil {
		// If no secrets exist, check for keyring file
		if c.config.KeyringPath != "" {
			logger.Info("Using keyring from file",
				zap.String("path", c.config.KeyringPath))
			return c.config.KeyringPath, nil
		}
		return "", fmt.Errorf("failed to retrieve keyring from SecretManager and no keyring file specified: %w", err)
	}

	// Return keyring path from secrets
	keyringPath, ok := serviceSecrets.Secrets["keyring"].(string)
	if !ok {
		return "", fmt.Errorf("keyring secret is not a string")
	}

	logger.Debug("Retrieved keyring from SecretManager",
		zap.String("backend", serviceSecrets.Backend))

	return keyringPath, nil
}

// verifyConnection verifies the connection to Ceph cluster
func (c *CephClient) verifyConnection() error {
	logger := otelzap.Ctx(c.rc.Ctx)

	// Check cluster FSID
	fsid, err := c.conn.GetFSID()
	if err != nil {
		return fmt.Errorf("failed to get cluster FSID: %w", err)
	}
	logger.Debug("Connected to Ceph cluster", zap.String("fsid", fsid))

	// Check if we can list pools (basic permission check)
	ctx, cancel := context.WithTimeout(c.rc.Ctx, c.config.OpTimeout)
	defer cancel()

	poolsChan := make(chan error, 1)
	go func() {
		_, err := c.conn.ListPools()
		poolsChan <- err
	}()

	select {
	case err := <-poolsChan:
		if err != nil {
			return fmt.Errorf("permission check failed (cannot list pools): %w", err)
		}
	case <-ctx.Done():
		return fmt.Errorf("verification timeout after %v", c.config.OpTimeout)
	}

	logger.Debug("Connection verification passed")
	return nil
}

// Close closes the Ceph client connection
func (c *CephClient) Close() error {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Debug("Closing Ceph client connection")

	if c.conn != nil {
		c.conn.Shutdown()
	}

	logger.Debug("Ceph client connection closed")
	return nil
}

// GetConn returns the underlying rados connection for advanced operations
func (c *CephClient) GetConn() *rados.Conn {
	return c.conn
}

// GetFSAdmin returns the FSAdmin client for CephFS operations
func (c *CephClient) GetFSAdmin() *admin.FSAdmin {
	return c.fsAdmin
}

// GetClusterFSID returns the cluster FSID
func (c *CephClient) GetClusterFSID() (string, error) {
	if c.conn == nil {
		return "", eos_err.NewUserError("client not connected")
	}
	return c.conn.GetFSID()
}

// Ping verifies cluster connectivity
func (c *CephClient) Ping() error {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Debug("Pinging Ceph cluster")

	if c.conn == nil {
		return eos_err.NewUserError("client not connected")
	}

	// Try to get FSID as a connectivity check
	_, err := c.conn.GetFSID()
	if err != nil {
		return fmt.Errorf("cluster ping failed: %w", err)
	}

	logger.Debug("Cluster ping successful")
	return nil
}

// discoverConsulMonitors discovers Ceph monitor addresses from Consul
func discoverConsulMonitors(rc *eos_io.RuntimeContext, config *ClientConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Set default service name if not specified
	if config.ConsulService == "" {
		config.ConsulService = "ceph-mon"
	}

	logger.Info("Discovering Ceph monitors from Consul",
		zap.String("service", config.ConsulService))

	// ASSESS: Check if Consul is available
	consulAddr := shared.GetConsulHostPort() // Returns hostname:port format
	// Note: Consul client expects host:port without protocol
	if envAddr := os.Getenv("CONSUL_HTTP_ADDR"); envAddr != "" {
		// If env var is set, use it (may include http://)
		consulAddr = envAddr
	}

	logger.Debug("Connecting to Consul",
		zap.String("addr", consulAddr))

	// Create Consul client
	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = consulAddr

	consulClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}

	// INTERVENE: Query Consul for Ceph monitors
	services, _, err := consulClient.Health().Service(config.ConsulService, "", true, nil)
	if err != nil {
		return fmt.Errorf("failed to query Consul for service %s: %w", config.ConsulService, err)
	}

	if len(services) == 0 {
		return fmt.Errorf("no healthy monitors found for service %s in Consul", config.ConsulService)
	}

	// EVALUATE: Build monitor address list
	monitors := make([]string, 0, len(services))
	for _, service := range services {
		// Ceph monitors typically listen on port 6789
		monAddr := fmt.Sprintf("%s:%d", service.Service.Address, service.Service.Port)

		// If service address is empty, use node address
		if service.Service.Address == "" {
			monAddr = fmt.Sprintf("%s:%d", service.Node.Address, service.Service.Port)
		}

		monitors = append(monitors, monAddr)
		logger.Debug("Discovered Ceph monitor",
			zap.String("address", monAddr),
			zap.String("node", service.Node.Node))
	}

	// Update config with discovered monitors
	config.MonHosts = monitors

	logger.Info("Successfully discovered Ceph monitors from Consul",
		zap.Int("count", len(monitors)),
		zap.Strings("monitors", monitors))

	return nil
}
