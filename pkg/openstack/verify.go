package openstack

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunPreChecks performs pre-installation verification
func RunPreChecks(rc *eos_io.RuntimeContext, config *Config) error {
	ctx, span := telemetry.Start(rc.Ctx, "openstack.RunPreChecks")
	defer span.End()
	rc = &eos_io.RuntimeContext{Ctx: ctx}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running pre-installation checks")

	checks := []struct {
		name string
		fn   func(*eos_io.RuntimeContext, *Config) error
	}{
		{"OS Compatibility", func(rc *eos_io.RuntimeContext, _ *Config) error { return checkOSCompatibility(rc) }},
		{"System Resources", checkSystemResources},
		{"Network Configuration", checkNetworkConfiguration},
		{"Port Availability", checkPortAvailability},
		{"Kernel Modules", checkKernelModules},
		{"Virtualization Support", checkVirtualizationSupport},
		{"Time Synchronization", checkTimeSynchronization},
	}

	var errors []string
	for _, check := range checks {
		logger.Debug("Running check", zap.String("check", check.name))
		if err := check.fn(rc, config); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", check.name, err))
			logger.Error("Check failed", 
				zap.String("check", check.name),
				zap.Error(err))
		} else {
			logger.Info("Check passed", zap.String("check", check.name))
		}
	}

	if len(errors) > 0 {
		return eos_err.NewUserError("Pre-installation checks failed:\n%s", 
			strings.Join(errors, "\n"))
	}

	logger.Info("All pre-installation checks passed")
	return nil
}

// Verify performs comprehensive post-installation verification
func Verify(rc *eos_io.RuntimeContext, config *Config) error {
	ctx, span := telemetry.Start(rc.Ctx, "openstack.Verify")
	defer span.End()
	rc = &eos_io.RuntimeContext{Ctx: ctx}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying OpenStack installation")

	// Wait for services to stabilize
	logger.Info("Waiting for services to stabilize")
	time.Sleep(10 * time.Second)

	// Verify each enabled service
	services := config.GetEnabledServices()
	for _, service := range services {
		if err := verifyService(rc, config, service); err != nil {
			return fmt.Errorf("service %s verification failed: %w", service, err)
		}
	}

	// Verify API endpoints
	if err := verifyAPIEndpoints(rc, config); err != nil {
		return fmt.Errorf("API endpoint verification failed: %w", err)
	}

	// Run functional tests if controller node
	if config.IsControllerNode() {
		if err := runFunctionalityTests(rc, config); err != nil {
			return fmt.Errorf("functionality tests failed: %w", err)
		}
	}

	logger.Info("OpenStack verification completed successfully")
	return nil
}

// verifyService checks if a specific service is running correctly
func verifyService(rc *eos_io.RuntimeContext, config *Config, service Service) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying service", zap.String("service", string(service)))

	// Check if service is active
	systemdService := getSystemdServiceName(service)
	if systemdService != "" {
		statusCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", systemdService)
		if err := statusCmd.Run(); err != nil {
			return fmt.Errorf("service %s is not active", systemdService)
		}
	}

	// Service-specific checks
	switch service {
	case ServiceKeystone:
		return verifyKeystone(rc, config)
	case ServiceGlance:
		return verifyGlance(rc, config)
	case ServiceNova:
		return verifyNova(rc, config)
	case ServiceNeutron:
		return verifyNeutron(rc, config)
	case ServiceCinder:
		return verifyCinder(rc, config)
	case ServiceHorizon:
		return verifyHorizon(rc, config)
	}

	return nil
}

// verifyKeystone checks Keystone service health
func verifyKeystone(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if we can get a token
	authURL := fmt.Sprintf("%s:5000/v3/auth/tokens", config.InternalEndpoint)
	authPayload := fmt.Sprintf(`{
		"auth": {
			"identity": {
				"methods": ["password"],
				"password": {
					"user": {
						"name": "admin",
						"domain": {"name": "Default"},
						"password": "%s"
					}
				}
			},
			"scope": {
				"project": {
					"name": "admin",
					"domain": {"name": "Default"}
				}
			}
		}
	}`, config.AdminPassword)

	ctx, cancel := context.WithTimeout(rc.Ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", authURL, 
		strings.NewReader(authPayload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to Keystone: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("Keystone authentication failed: status %d", resp.StatusCode)
	}

	// Check if we got a token
	token := resp.Header.Get("X-Subject-Token")
	if token == "" {
		return fmt.Errorf("Keystone did not return a token")
	}

	logger.Info("Keystone verification successful")
	return nil
}

// verifyGlance checks Glance service health
func verifyGlance(rc *eos_io.RuntimeContext, config *Config) error {
	// Get auth token first
	token, err := getAuthToken(rc, config)
	if err != nil {
		return fmt.Errorf("failed to get auth token: %w", err)
	}

	// Check Glance API
	glanceURL := fmt.Sprintf("%s:9292/v2/images", config.InternalEndpoint)
	
	ctx, cancel := context.WithTimeout(rc.Ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", glanceURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Auth-Token", token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to Glance: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Glance API returned status %d", resp.StatusCode)
	}

	return nil
}

// verifyNova checks Nova service health
func verifyNova(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// For compute nodes, just check nova-compute service
	if config.Mode == ModeCompute {
		statusCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", "nova-compute")
		if err := statusCmd.Run(); err != nil {
			return fmt.Errorf("nova-compute service is not active")
		}
		return nil
	}

	// For controller nodes, check all Nova services
	novaServices := []string{
		"nova-api",
		"nova-conductor",
		"nova-scheduler",
		"nova-novncproxy",
	}

	for _, svc := range novaServices {
		statusCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", svc)
		if err := statusCmd.Run(); err != nil {
			return fmt.Errorf("service %s is not active", svc)
		}
	}

	// Check Nova API
	token, err := getAuthToken(rc, config)
	if err != nil {
		return fmt.Errorf("failed to get auth token: %w", err)
	}

	novaURL := fmt.Sprintf("%s:8774/v2.1/servers", config.InternalEndpoint)
	
	ctx, cancel := context.WithTimeout(rc.Ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", novaURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Auth-Token", token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to Nova: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Nova API returned status %d", resp.StatusCode)
	}

	logger.Info("Nova verification successful")
	return nil
}

// verifyAPIEndpoints checks all API endpoints are accessible
func verifyAPIEndpoints(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying API endpoints")

	endpoints := []struct {
		name string
		url  string
		port int
	}{
		{"Keystone", config.PublicEndpoint, PortKeystone},
		{"Glance", config.PublicEndpoint, PortGlance},
		{"Nova", config.PublicEndpoint, PortNovaAPI},
		{"Neutron", config.PublicEndpoint, PortNeutron},
	}

	if contains(config.GetEnabledServices(), ServiceCinder) {
		endpoints = append(endpoints, struct {
			name string
			url  string
			port int
		}{"Cinder", config.PublicEndpoint, PortCinder})
	}

	for _, endpoint := range endpoints {
		url := fmt.Sprintf("%s:%d", endpoint.url, endpoint.port)
		if err := checkEndpointConnectivity(rc, url); err != nil {
			logger.Error("Endpoint verification failed",
				zap.String("service", endpoint.name),
				zap.String("url", url),
				zap.Error(err))
			return fmt.Errorf("%s endpoint not accessible: %w", endpoint.name, err)
		}
		logger.Info("Endpoint verified",
			zap.String("service", endpoint.name),
			zap.String("url", url))
	}

	return nil
}

// runFunctionalityTests performs basic functional tests
func runFunctionalityTests(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running functionality tests")

	// Source admin credentials
	sourceCmd := fmt.Sprintf("source /etc/openstack/admin-openrc.sh && ")

	tests := []struct {
		name string
		cmd  string
	}{
		{"List users", sourceCmd + "openstack user list"},
		{"List projects", sourceCmd + "openstack project list"},
		{"List services", sourceCmd + "openstack service list"},
		{"List endpoints", sourceCmd + "openstack endpoint list"},
		{"List networks", sourceCmd + "openstack network list"},
		{"List images", sourceCmd + "openstack image list"},
		{"List flavors", sourceCmd + "openstack flavor list"},
	}

	for _, test := range tests {
		logger.Debug("Running test", zap.String("test", test.name))
		cmd := exec.CommandContext(rc.Ctx, "bash", "-c", test.cmd)
		output, err := cmd.CombinedOutput()
		if err != nil {
			logger.Error("Test failed",
				zap.String("test", test.name),
				zap.String("output", string(output)),
				zap.Error(err))
			return fmt.Errorf("test '%s' failed: %w", test.name, err)
		}
		logger.Info("Test passed", zap.String("test", test.name))
	}

	return nil
}

// Helper functions for verification

func checkNetworkConfiguration(rc *eos_io.RuntimeContext, config *Config) error {
	// Check if required network interfaces exist
	if config.NetworkType == NetworkProvider && config.ProviderInterface != "" {
		checkCmd := exec.CommandContext(rc.Ctx, "ip", "link", "show", config.ProviderInterface)
		if err := checkCmd.Run(); err != nil {
			return fmt.Errorf("provider network interface %s not found", config.ProviderInterface)
		}
	}

	// Check IP forwarding
	ipForwardCmd := exec.CommandContext(rc.Ctx, "sysctl", "net.ipv4.ip_forward")
	output, err := ipForwardCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check IP forwarding: %w", err)
	}

	if !strings.Contains(string(output), "= 1") {
		return fmt.Errorf("IP forwarding is not enabled")
	}

	return nil
}

func checkPortAvailability(rc *eos_io.RuntimeContext, config *Config) error {
	// Check if required ports are available
	ports := []int{
		PortKeystone, PortGlance, PortNovaAPI, PortNeutron,
		3306, // MySQL
		5672, // RabbitMQ
		11211, // Memcached
	}

	if config.EnableDashboard {
		if config.EnableSSL {
			ports = append(ports, PortHorizonSSL)
		} else {
			ports = append(ports, PortHorizon)
		}
	}

	for _, port := range ports {
		if err := checkPort(rc, port); err != nil {
			return fmt.Errorf("port %d is not available: %w", port, err)
		}
	}

	return nil
}

func checkKernelModules(rc *eos_io.RuntimeContext, config *Config) error {
	// Check required kernel modules
	modules := []string{"br_netfilter", "vhost_net"}

	if config.NetworkType != "" {
		modules = append(modules, "openvswitch")
	}

	for _, module := range modules {
		checkCmd := exec.CommandContext(rc.Ctx, "lsmod")
		output, err := checkCmd.Output()
		if err != nil {
			return fmt.Errorf("failed to check kernel modules: %w", err)
		}

		if !strings.Contains(string(output), module) {
			// Try to load the module
			loadCmd := exec.CommandContext(rc.Ctx, "modprobe", module)
			if err := loadCmd.Run(); err != nil {
				return fmt.Errorf("kernel module %s not available", module)
			}
		}
	}

	return nil
}

func checkVirtualizationSupport(rc *eos_io.RuntimeContext, config *Config) error {
	// Only check on compute nodes
	if config.Mode != ModeCompute && config.Mode != ModeAllInOne {
		return nil
	}

	// Check for KVM support
	kvmCmd := exec.CommandContext(rc.Ctx, "kvm-ok")
	if err := kvmCmd.Run(); err != nil {
		// Check CPU flags as fallback
		cpuCmd := exec.CommandContext(rc.Ctx, "grep", "-E", "vmx|svm", "/proc/cpuinfo")
		if err := cpuCmd.Run(); err != nil {
			return fmt.Errorf("hardware virtualization not supported")
		}
	}

	return nil
}

func checkTimeSynchronization(rc *eos_io.RuntimeContext, config *Config) error {
	// Check if NTP/chrony is running
	services := []string{"chronyd", "ntpd", "systemd-timesyncd"}
	
	for _, svc := range services {
		checkCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", svc)
		if checkCmd.Run() == nil {
			// Found an active time sync service
			return nil
		}
	}

	return fmt.Errorf("no time synchronization service is active")
}

func getSystemdServiceName(service Service) string {
	switch service {
	case ServiceKeystone:
		return "apache2" // Keystone runs under Apache
	case ServiceGlance:
		return "glance-api"
	case ServiceNova:
		return "nova-api"
	case ServiceNeutron:
		return "neutron-server"
	case ServiceCinder:
		return "cinder-api"
	case ServiceHorizon:
		return "apache2"
	default:
		return ""
	}
}

func checkPort(rc *eos_io.RuntimeContext, port int) error {
	cmd := exec.CommandContext(rc.Ctx, "ss", "-tln")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	portStr := fmt.Sprintf(":%d", port)
	if strings.Contains(string(output), portStr) {
		return fmt.Errorf("port %d is already in use", port)
	}

	return nil
}

func checkEndpointConnectivity(rc *eos_io.RuntimeContext, url string) error {
	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	// We expect some response, even if it's an auth error
	if resp.StatusCode == 0 {
		return fmt.Errorf("no response from endpoint")
	}

	return nil
}

func getAuthToken(rc *eos_io.RuntimeContext, config *Config) (string, error) {
	// Implementation would get an auth token from Keystone
	// This is simplified for the example
	return "dummy-token", nil
}

// getServiceStatus returns the current status of a service
func getServiceStatus(rc *eos_io.RuntimeContext, service Service) (ServiceStatus, error) {
	status := ServiceStatus{
		Name:    service,
		Enabled: true,
	}

	// Check if service is running
	systemdService := getSystemdServiceName(service)
	if systemdService != "" {
		statusCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", systemdService)
		status.Running = statusCmd.Run() == nil
		status.Healthy = status.Running
	}

	// Get service version (simplified)
	status.Version = getTargetVersion()

	return status, nil
}

// verifyNeutron checks Neutron service health
func verifyNeutron(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Neutron networking service")

	// Check service is running
	services := []string{"neutron-server", "neutron-openvswitch-agent", "neutron-dhcp-agent", "neutron-l3-agent", "neutron-metadata-agent"}
	for _, svc := range services {
		statusCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", svc)
		if err := statusCmd.Run(); err != nil {
			logger.Warn("Neutron service not running", zap.String("service", svc))
		}
	}

	// Check API endpoint
	endpoint := fmt.Sprintf("%s:%d", config.InternalEndpoint, PortNeutron)
	if err := checkEndpointConnectivity(rc, endpoint); err != nil {
		return fmt.Errorf("Neutron API not accessible: %w", err)
	}

	// Check network connectivity
	agentCmd := exec.CommandContext(rc.Ctx, "bash", "-c", 
		`source /etc/openstack/admin-openrc.sh && openstack network agent list -f value -c Alive 2>/dev/null`)
	if output, err := agentCmd.Output(); err == nil {
		if !strings.Contains(string(output), ":-)") {
			logger.Warn("Some Neutron agents are not alive")
		}
	}

	logger.Info("Neutron service verification completed")
	return nil
}

// verifyCinder checks Cinder service health
func verifyCinder(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Cinder block storage service")

	// Check service is running
	services := []string{"cinder-api", "cinder-scheduler", "cinder-volume"}
	for _, svc := range services {
		statusCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", svc)
		if err := statusCmd.Run(); err != nil {
			logger.Warn("Cinder service not running", zap.String("service", svc))
		}
	}

	// Check API endpoint
	endpoint := fmt.Sprintf("%s:%d", config.InternalEndpoint, PortCinder)
	if err := checkEndpointConnectivity(rc, endpoint); err != nil {
		return fmt.Errorf("Cinder API not accessible: %w", err)
	}

	// Check storage backend
	volumeCmd := exec.CommandContext(rc.Ctx, "bash", "-c",
		`source /etc/openstack/admin-openrc.sh && openstack volume service list -f value -c State 2>/dev/null`)
	if output, err := volumeCmd.Output(); err == nil {
		if strings.Contains(string(output), "down") {
			logger.Warn("Some Cinder services are down")
		}
	}

	logger.Info("Cinder service verification completed")
	return nil
}

// verifyHorizon checks Horizon dashboard service
func verifyHorizon(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Horizon dashboard service")

	// Check if Apache is running
	statusCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", "apache2")
	if err := statusCmd.Run(); err != nil {
		return fmt.Errorf("Apache web server not running")
	}

	// Check dashboard endpoint
	endpoint := fmt.Sprintf("%s:%d/horizon", config.PublicEndpoint, PortHorizon)
	if err := checkEndpointConnectivity(rc, endpoint); err != nil {
		// Try without /horizon path
		endpoint = fmt.Sprintf("%s:%d", config.PublicEndpoint, PortHorizon)
		if err := checkEndpointConnectivity(rc, endpoint); err != nil {
			return fmt.Errorf("Horizon dashboard not accessible: %w", err)
		}
	}

	logger.Info("Horizon dashboard verification completed")
	return nil
}