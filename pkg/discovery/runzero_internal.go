package discovery

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InternalDiscoveryManager handles internal network asset discovery using runZero patterns
type InternalDiscoveryManager struct {
	explorers map[string]*InternalExplorer
	config    *InternalDiscoveryConfig
	logger    *zap.Logger
}

// InternalDiscoveryConfig defines the discovery configuration
type InternalDiscoveryConfig struct {
	Locations         []ExplorerLocation `yaml:"locations" json:"locations"`
	BaselineEnabled   bool               `yaml:"baseline_enabled" json:"baseline_enabled"`
	ComplianceEnabled bool               `yaml:"compliance_enabled" json:"compliance_enabled"`
	ShadowITEnabled   bool               `yaml:"shadow_it_enabled" json:"shadow_it_enabled"`
	AggressiveMode    bool               `yaml:"aggressive_mode" json:"aggressive_mode"`
	ScanInterval      time.Duration      `yaml:"scan_interval" json:"scan_interval"`
}

// ExplorerLocation defines a network location for discovery
type ExplorerLocation struct {
	Name        string   `yaml:"name" json:"name"`
	Networks    []string `yaml:"networks" json:"networks"`
	RateLimit   int      `yaml:"rate_limit" json:"rate_limit"`
	Scanner     string   `yaml:"scanner" json:"scanner"`
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	Description string   `yaml:"description" json:"description"`
}

// InternalExplorer handles discovery for a specific location
type InternalExplorer struct {
	location   ExplorerLocation
	lastScan   time.Time
	baseline   map[string]*Asset
	violations []ComplianceViolation
	shadowIT   []Asset
	logger     *zap.Logger
}

// Asset represents a discovered network asset
type Asset struct {
	Address        string            `json:"address"`
	Hostname       string            `json:"hostname"`
	MAC            string            `json:"mac"`
	OS             OSInfo            `json:"os"`
	Services       []Service         `json:"services"`
	Tags           []string          `json:"tags"`
	LastSeen       time.Time         `json:"last_seen"`
	FirstSeen      time.Time         `json:"first_seen"`
	IsAuthorized   bool              `json:"is_authorized"`
	RiskScore      int               `json:"risk_score"`
	Metadata       map[string]string `json:"metadata"`
	ComplianceData ComplianceData    `json:"compliance_data"`
}

// OSInfo represents operating system information
type OSInfo struct {
	Type        string `json:"type"`
	Version     string `json:"version"`
	Vendor      string `json:"vendor"`
	LastPatched string `json:"last_patched"`
}

// Service represents a network service
type Service struct {
	Port      int               `json:"port"`
	Protocol  string            `json:"protocol"`
	Service   string            `json:"service"`
	Version   string            `json:"version"`
	Banner    string            `json:"banner"`
	State     string            `json:"state"`
	Metadata  map[string]string `json:"metadata"`
	Encrypted bool              `json:"encrypted"`
}

// ComplianceViolation represents a compliance issue
type ComplianceViolation struct {
	Asset       Asset     `json:"asset"`
	Policy      string    `json:"policy"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Remediation string    `json:"remediation"`
	DetectedAt  time.Time `json:"detected_at"`
}

// ComplianceData represents compliance status
type ComplianceData struct {
	HasEncryption    bool      `json:"has_encryption"`
	LastPatchDate    time.Time `json:"last_patch_date"`
	DaysSincePatched int       `json:"days_since_patched"`
	EndOfLife        bool      `json:"end_of_life"`
	DefaultCreds     bool      `json:"default_credentials"`
	OpenPorts        []int     `json:"open_ports"`
	CriticalServices []string  `json:"critical_services"`
}

// SecurityAlert represents a security alert
type SecurityAlert struct {
	Type        string            `json:"type"`
	Asset       Asset             `json:"asset"`
	Severity    string            `json:"severity"`
	Details     string            `json:"details"`
	Timestamp   time.Time         `json:"timestamp"`
	Remediation string            `json:"remediation"`
	Metadata    map[string]string `json:"metadata"`
}

// DiscoveryResult represents the result of a discovery scan
type DiscoveryResult struct {
	Location      string                `json:"location"`
	ScanStartTime time.Time             `json:"scan_start_time"`
	ScanEndTime   time.Time             `json:"scan_end_time"`
	Duration      time.Duration         `json:"duration"`
	AssetsFound   []Asset               `json:"assets_found"`
	NewAssets     []Asset               `json:"new_assets"`
	Violations    []ComplianceViolation `json:"violations"`
	ShadowIT      []Asset               `json:"shadow_it"`
	Alerts        []SecurityAlert       `json:"alerts"`
	Statistics    DiscoveryStatistics   `json:"statistics"`
}

// DiscoveryStatistics provides scan statistics
type DiscoveryStatistics struct {
	TotalHosts         int `json:"total_hosts"`
	ResponsiveHosts    int `json:"responsive_hosts"`
	UnauthorizedHosts  int `json:"unauthorized_hosts"`
	VulnerableServices int `json:"vulnerable_services"`
	ComplianceScore    int `json:"compliance_score"`
	RiskScore          int `json:"risk_score"`
}

// NewInternalDiscoveryManager creates a new internal discovery manager
func NewInternalDiscoveryManager(config *InternalDiscoveryConfig, logger *zap.Logger) *InternalDiscoveryManager {
	if config == nil {
		config = DefaultInternalDiscoveryConfig()
	}

	manager := &InternalDiscoveryManager{
		explorers: make(map[string]*InternalExplorer),
		config:    config,
		logger:    logger.Named("internal_discovery"),
	}

	// Initialize explorers for each location
	for _, location := range config.Locations {
		if location.Enabled {
			explorer := &InternalExplorer{
				location: location,
				baseline: make(map[string]*Asset),
				logger:   logger.Named(fmt.Sprintf("explorer_%s", location.Name)),
			}
			manager.explorers[location.Name] = explorer
		}
	}

	return manager
}

// DefaultInternalDiscoveryConfig returns a default configuration
func DefaultInternalDiscoveryConfig() *InternalDiscoveryConfig {
	return &InternalDiscoveryConfig{
		Locations: []ExplorerLocation{
			{
				Name:        "Core-Network",
				Networks:    []string{"10.0.0.0/16"},
				RateLimit:   5000,
				Scanner:     "core-explorer",
				Enabled:     true,
				Description: "Core internal network",
			},
			{
				Name:        "DMZ",
				Networks:    []string{"172.16.0.0/24"},
				RateLimit:   1000,
				Scanner:     "dmz-explorer",
				Enabled:     true,
				Description: "DMZ network",
			},
			{
				Name:        "Dev-Environment",
				Networks:    []string{"10.50.0.0/16"},
				RateLimit:   10000,
				Scanner:     "dev-explorer",
				Enabled:     true,
				Description: "Development environment",
			},
		},
		BaselineEnabled:   true,
		ComplianceEnabled: true,
		ShadowITEnabled:   true,
		AggressiveMode:    false,
		ScanInterval:      1 * time.Hour,
	}
}

// DiscoverAll performs discovery across all configured locations
func (m *InternalDiscoveryManager) DiscoverAll(rc *eos_io.RuntimeContext) ([]*DiscoveryResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting internal asset discovery",
		zap.Int("locations", len(m.explorers)),
		zap.Bool("aggressive_mode", m.config.AggressiveMode))

	var results []*DiscoveryResult
	for name, explorer := range m.explorers {
		logger.Info("Discovering location", zap.String("location", name))

		result, err := m.discoverLocation(rc, explorer)
		if err != nil {
			logger.Error("Discovery failed for location",
				zap.String("location", name),
				zap.Error(err))
			continue
		}

		results = append(results, result)
	}

	// Perform post-processing
	if err := m.postProcessResults(rc, results); err != nil {
		logger.Warn("Post-processing failed", zap.Error(err))
	}

	logger.Info("Internal discovery completed",
		zap.Int("locations_scanned", len(results)))

	return results, nil
}

// DiscoverLocation performs discovery for a specific location
func (m *InternalDiscoveryManager) DiscoverLocation(rc *eos_io.RuntimeContext, locationName string) (*DiscoveryResult, error) {
	explorer, exists := m.explorers[locationName]
	if !exists {
		return nil, fmt.Errorf("location not found: %s", locationName)
	}

	return m.discoverLocation(rc, explorer)
}

// discoverLocation performs the actual discovery for a location
func (m *InternalDiscoveryManager) discoverLocation(rc *eos_io.RuntimeContext, explorer *InternalExplorer) (*DiscoveryResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	result := &DiscoveryResult{
		Location:      explorer.location.Name,
		ScanStartTime: startTime,
		AssetsFound:   []Asset{},
		NewAssets:     []Asset{},
		Violations:    []ComplianceViolation{},
		ShadowIT:      []Asset{},
		Alerts:        []SecurityAlert{},
	}

	logger.Info("Starting discovery for location",
		zap.String("location", explorer.location.Name),
		zap.Strings("networks", explorer.location.Networks))

	// Discover assets in each network
	for _, network := range explorer.location.Networks {
		assets, err := m.discoverNetwork(rc, network, explorer)
		if err != nil {
			logger.Error("Network discovery failed",
				zap.String("network", network),
				zap.Error(err))
			continue
		}

		result.AssetsFound = append(result.AssetsFound, assets...)
	}

	// Process discovered assets
	m.processAssets(rc, explorer, result)

	// Finalize result
	endTime := time.Now()
	result.ScanEndTime = endTime
	result.Duration = endTime.Sub(startTime)
	result.Statistics = m.calculateStatistics(result)

	explorer.lastScan = endTime

	logger.Info("Discovery completed for location",
		zap.String("location", explorer.location.Name),
		zap.Int("assets_found", len(result.AssetsFound)),
		zap.Int("new_assets", len(result.NewAssets)),
		zap.Duration("duration", result.Duration))

	return result, nil
}

// discoverNetwork discovers assets in a specific network
func (m *InternalDiscoveryManager) discoverNetwork(rc *eos_io.RuntimeContext, network string, explorer *InternalExplorer) ([]Asset, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse network CIDR
	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		return nil, fmt.Errorf("invalid network CIDR: %w", err)
	}

	logger.Debug("Scanning network",
		zap.String("network", network),
		zap.String("location", explorer.location.Name))

	var assets []Asset

	// Generate IPs to scan
	ips := generateIPsFromCIDR(ipNet)
	if m.config.AggressiveMode {
		// In aggressive mode, scan all IPs
		logger.Debug("Aggressive mode: scanning all IPs", zap.Int("ip_count", len(ips)))
	} else {
		// In normal mode, sample IPs or use smart discovery
		ips = sampleIPs(ips, 100) // Sample 100 IPs
		logger.Debug("Normal mode: sampling IPs", zap.Int("ip_count", len(ips)))
	}

	// Scan each IP
	for _, ip := range ips {
		select {
		case <-rc.Ctx.Done():
			return assets, fmt.Errorf("discovery cancelled: %w", rc.Ctx.Err())
		default:
		}

		asset, err := m.scanHost(rc, ip, explorer)
		if err != nil {
			// Log but continue with other hosts
			logger.Debug("Host scan failed",
				zap.String("ip", ip),
				zap.Error(err))
			continue
		}

		if asset != nil {
			assets = append(assets, *asset)
		}

		// Rate limiting
		if explorer.location.RateLimit > 0 {
			time.Sleep(time.Second / time.Duration(explorer.location.RateLimit))
		}
	}

	return assets, nil
}

// scanHost scans a specific host for services and information
func (m *InternalDiscoveryManager) scanHost(rc *eos_io.RuntimeContext, ip string, explorer *InternalExplorer) (*Asset, error) {
	// Basic connectivity check
	if !m.isHostResponsive(ip) {
		return nil, nil // Not responsive, skip
	}

	asset := &Asset{
		Address:   ip,
		LastSeen:  time.Now(),
		Services:  []Service{},
		Tags:      []string{},
		Metadata:  make(map[string]string),
	}

	// Try to get hostname
	if hostname, err := m.getHostname(ip); err == nil {
		asset.Hostname = hostname
	}

	// Try to get MAC address (if on same subnet)
	if mac, err := m.getMACAddress(ip); err == nil {
		asset.MAC = mac
	}

	// Discover services (HD Moore's favorite ports)
	asset.Services = m.discoverServices(rc, ip, explorer)

	// OS fingerprinting
	asset.OS = m.fingerprinthOS(asset.Services)

	// Compliance checking
	asset.ComplianceData = m.checkCompliance(asset)

	// Risk scoring
	asset.RiskScore = m.calculateRiskScore(asset)

	// Check if authorized
	asset.IsAuthorized = m.isAuthorizedAsset(asset)

	// Set first seen if new
	if explorer.baseline[ip] == nil {
		asset.FirstSeen = asset.LastSeen
	} else {
		asset.FirstSeen = explorer.baseline[ip].FirstSeen
	}

	return asset, nil
}

// isHostResponsive checks if a host is responsive
func (m *InternalDiscoveryManager) isHostResponsive(ip string) bool {
	// Try ICMP ping first
	// For now, simplified check
	conn, err := net.DialTimeout("tcp", ip+":80", 1*time.Second)
	if err == nil {
		conn.Close()
		return true
	}

	// Try other common ports
	commonPorts := []string{"22", "23", "53", "443", "3389"}
	for _, port := range commonPorts {
		conn, err := net.DialTimeout("tcp", ip+":"+port, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
	}

	return false
}

// discoverServices discovers services on a host (HD Moore style)
func (m *InternalDiscoveryManager) discoverServices(rc *eos_io.RuntimeContext, ip string, explorer *InternalExplorer) []Service {
	var services []Service

	// HD Moore's favorite ports for internal discovery
	hdMoorePorts := []int{
		// Standard services
		21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
		// Database ports
		1433, 1521, 3306, 5432, 6379, 27017,
		// Management interfaces
		161, 623, // SNMP, IPMI
		8080, 8443, 9200, // Web management
		// Windows specific
		135, 139, 445, 3389,
		// VMware/virtualization
		902, 903, 5988, 5989,
		// Industrial/IoT
		102, 502, 47808, // S7, Modbus, BACnet
	}

	// Aggressive mode scans more ports
	if m.config.AggressiveMode {
		hdMoorePorts = append(hdMoorePorts, []int{
			// Additional aggressive ports
			111, 513, 514, 515, 1433, 2049, 2082, 2083, 2086, 2087,
			3000, 3001, 4443, 5000, 5001, 5432, 6000, 6001, 7001, 8000,
			8001, 8008, 8009, 8081, 8090, 8091, 8443, 8888, 9000, 9001,
		}...)
	}

	for _, port := range hdMoorePorts {
		select {
		case <-rc.Ctx.Done():
			return services
		default:
		}

		service := m.scanPort(ip, port)
		if service != nil {
			services = append(services, *service)
		}
	}

	return services
}

// scanPort scans a specific port
func (m *InternalDiscoveryManager) scanPort(ip string, port int) *Service {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	service := &Service{
		Port:     port,
		Protocol: "tcp",
		State:    "open",
		Metadata: make(map[string]string),
	}

	// Try to grab banner
	service.Banner = m.grabBanner(conn)

	// Service identification
	service.Service = m.identifyService(port, service.Banner)

	// Check if encrypted
	service.Encrypted = m.isEncryptedService(port, service.Banner)

	return service
}

// Helper functions for asset discovery

func (m *InternalDiscoveryManager) getHostname(ip string) (string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return "", fmt.Errorf("no hostname found")
	}
	return strings.TrimSuffix(names[0], "."), nil
}

func (m *InternalDiscoveryManager) getMACAddress(ip string) (string, error) {
	// This would require ARP table lookup or raw packet capture
	// Simplified implementation
	return "", fmt.Errorf("MAC address discovery not implemented")
}

func (m *InternalDiscoveryManager) grabBanner(conn net.Conn) string {
	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	
	banner := string(buffer[:n])
	// Clean up banner
	banner = strings.TrimSpace(banner)
	if len(banner) > 200 {
		banner = banner[:200] + "..."
	}
	
	return banner
}

func (m *InternalDiscoveryManager) identifyService(port int, banner string) string {
	// Service identification based on port and banner
	commonServices := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		1521:  "oracle",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		6379:  "redis",
		27017: "mongodb",
	}

	if service, exists := commonServices[port]; exists {
		return service
	}

	// Try to identify from banner
	if strings.Contains(strings.ToLower(banner), "ssh") {
		return "ssh"
	}
	if strings.Contains(strings.ToLower(banner), "http") {
		return "http"
	}

	return "unknown"
}

func (m *InternalDiscoveryManager) isEncryptedService(port int, banner string) bool {
	encryptedPorts := map[int]bool{
		22:   true, // SSH
		443:  true, // HTTPS
		993:  true, // IMAPS
		995:  true, // POP3S
		8443: true, // HTTPS alt
	}

	return encryptedPorts[port] || strings.Contains(strings.ToLower(banner), "ssl") || strings.Contains(strings.ToLower(banner), "tls")
}

func (m *InternalDiscoveryManager) fingerprinthOS(services []Service) OSInfo {
	os := OSInfo{Type: "unknown"}

	for _, service := range services {
		banner := strings.ToLower(service.Banner)
		
		if strings.Contains(banner, "windows") || service.Port == 3389 || service.Port == 445 {
			os.Type = "windows"
			break
		}
		if strings.Contains(banner, "linux") || strings.Contains(banner, "ubuntu") || strings.Contains(banner, "centos") {
			os.Type = "linux"
			break
		}
		if strings.Contains(banner, "cisco") {
			os.Type = "cisco"
			break
		}
		if strings.Contains(banner, "vmware") {
			os.Type = "vmware"
			break
		}
	}

	return os
}

func (m *InternalDiscoveryManager) checkCompliance(asset *Asset) ComplianceData {
	compliance := ComplianceData{
		OpenPorts: []int{},
	}

	// Check for encryption
	for _, service := range asset.Services {
		compliance.OpenPorts = append(compliance.OpenPorts, service.Port)
		if service.Encrypted {
			compliance.HasEncryption = true
		}
	}

	// Check for default credentials (simplified)
	for _, service := range asset.Services {
		if service.Service == "telnet" || (service.Service == "ssh" && strings.Contains(service.Banner, "default")) {
			compliance.DefaultCreds = true
		}
	}

	// Calculate days since patched (simplified - would need actual OS detection)
	compliance.DaysSincePatched = 999 // Unknown

	return compliance
}

func (m *InternalDiscoveryManager) calculateRiskScore(asset *Asset) int {
	score := 0

	// Base score
	score += len(asset.Services) * 5

	// High-risk services
	highRiskServices := map[string]int{
		"telnet":  50,
		"ftp":     30,
		"http":    20,
		"snmp":    40,
		"rdp":     30,
	}

	for _, service := range asset.Services {
		if risk, exists := highRiskServices[service.Service]; exists {
			score += risk
		}
		if !service.Encrypted && service.Service != "dns" {
			score += 10
		}
	}

	// Default credentials
	if asset.ComplianceData.DefaultCreds {
		score += 100
	}

	// Unpatched systems
	if asset.ComplianceData.DaysSincePatched > 30 {
		score += 50
	}

	// Cap at 1000
	if score > 1000 {
		score = 1000
	}

	return score
}

func (m *InternalDiscoveryManager) isAuthorizedAsset(asset *Asset) bool {
	// Simplified authorization check
	// In real implementation, this would check against CMDB, AD, etc.
	
	// Consider it authorized if it has a hostname or is in known ranges
	if asset.Hostname != "" {
		return true
	}

	// Check against known unauthorized patterns
	unauthorizedPatterns := []string{
		"android", "iphone", "ipad", "macbook",
		"personal", "guest", "temp",
	}

	hostname := strings.ToLower(asset.Hostname)
	for _, pattern := range unauthorizedPatterns {
		if strings.Contains(hostname, pattern) {
			return false
		}
	}

	return true
}

// processAssets processes discovered assets for violations, shadow IT, etc.
func (m *InternalDiscoveryManager) processAssets(rc *eos_io.RuntimeContext, explorer *InternalExplorer, result *DiscoveryResult) {
	logger := otelzap.Ctx(rc.Ctx)

	for _, asset := range result.AssetsFound {
		// Check if new asset
		if explorer.baseline[asset.Address] == nil {
			result.NewAssets = append(result.NewAssets, asset)
			logger.Info("New asset discovered",
				zap.String("address", asset.Address),
				zap.String("hostname", asset.Hostname))
		}

		// Update baseline
		explorer.baseline[asset.Address] = &asset

		// Check for compliance violations
		violations := m.checkAssetCompliance(asset)
		result.Violations = append(result.Violations, violations...)

		// Check for shadow IT
		if m.isShadowIT(asset) {
			result.ShadowIT = append(result.ShadowIT, asset)
		}

		// Generate alerts
		alerts := m.generateAlerts(asset)
		result.Alerts = append(result.Alerts, alerts...)
	}
}

func (m *InternalDiscoveryManager) checkAssetCompliance(asset Asset) []ComplianceViolation {
	var violations []ComplianceViolation

	// Check for unencrypted services
	for _, service := range asset.Services {
		if !service.Encrypted && service.Service != "dns" {
			violations = append(violations, ComplianceViolation{
				Asset:       asset,
				Policy:      "Encryption Required",
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("Unencrypted service %s on port %d", service.Service, service.Port),
				Remediation: "Enable encryption for this service",
				DetectedAt:  time.Now(),
			})
		}
	}

	// Check for default credentials
	if asset.ComplianceData.DefaultCreds {
		violations = append(violations, ComplianceViolation{
			Asset:       asset,
			Policy:      "No Default Credentials",
			Severity:    "HIGH",
			Description: "System appears to have default credentials",
			Remediation: "Change default credentials immediately",
			DetectedAt:  time.Now(),
		})
	}

	// Check for old systems
	if asset.ComplianceData.DaysSincePatched > 30 {
		violations = append(violations, ComplianceViolation{
			Asset:       asset,
			Policy:      "30-day patch cycle",
			Severity:    "HIGH",
			Description: fmt.Sprintf("System not patched in %d days", asset.ComplianceData.DaysSincePatched),
			Remediation: "Apply security patches",
			DetectedAt:  time.Now(),
		})
	}

	return violations
}

func (m *InternalDiscoveryManager) isShadowIT(asset Asset) bool {
	// Shadow IT detection patterns
	shadowPatterns := []string{
		"iphone", "android", "macbook", "personal",
		"dropbox", "teamviewer", "ngrok", "localtunnel",
		"netgear", "linksys", "tp-link", "dlink",
	}

	hostname := strings.ToLower(asset.Hostname)
	for _, pattern := range shadowPatterns {
		if strings.Contains(hostname, pattern) {
			return true
		}
	}

	// Check for unauthorized services
	for _, service := range asset.Services {
		banner := strings.ToLower(service.Banner)
		for _, pattern := range shadowPatterns {
			if strings.Contains(banner, pattern) {
				return true
			}
		}
	}

	return false
}

func (m *InternalDiscoveryManager) generateAlerts(asset Asset) []SecurityAlert {
	var alerts []SecurityAlert

	// Unauthorized device alert
	if !asset.IsAuthorized {
		alerts = append(alerts, SecurityAlert{
			Type:        "Unauthorized Device",
			Asset:       asset,
			Severity:    "HIGH",
			Details:     fmt.Sprintf("Unknown device detected: %s (%s)", asset.Address, asset.Hostname),
			Timestamp:   time.Now(),
			Remediation: "Investigate device and add to authorized list or quarantine",
		})
	}

	// High risk score alert
	if asset.RiskScore > 500 {
		alerts = append(alerts, SecurityAlert{
			Type:        "High Risk Asset",
			Asset:       asset,
			Severity:    "MEDIUM",
			Details:     fmt.Sprintf("Asset has high risk score: %d", asset.RiskScore),
			Timestamp:   time.Now(),
			Remediation: "Review security configuration and apply hardening",
		})
	}

	return alerts
}

func (m *InternalDiscoveryManager) calculateStatistics(result *DiscoveryResult) DiscoveryStatistics {
	stats := DiscoveryStatistics{
		TotalHosts:        len(result.AssetsFound),
		ResponsiveHosts:   len(result.AssetsFound),
		UnauthorizedHosts: len(result.ShadowIT),
	}

	// Calculate compliance score
	if stats.TotalHosts > 0 {
		violationCount := len(result.Violations)
		stats.ComplianceScore = (stats.TotalHosts - violationCount) * 100 / stats.TotalHosts
	}

	// Calculate average risk score
	totalRisk := 0
	for _, asset := range result.AssetsFound {
		totalRisk += asset.RiskScore
	}
	if stats.TotalHosts > 0 {
		stats.RiskScore = totalRisk / stats.TotalHosts
	}

	return stats
}

func (m *InternalDiscoveryManager) postProcessResults(rc *eos_io.RuntimeContext, results []*DiscoveryResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Aggregate results
	totalAssets := 0
	totalViolations := 0
	totalAlerts := 0

	for _, result := range results {
		totalAssets += len(result.AssetsFound)
		totalViolations += len(result.Violations)
		totalAlerts += len(result.Alerts)
	}

	logger.Info("Discovery summary",
		zap.Int("total_assets", totalAssets),
		zap.Int("total_violations", totalViolations),
		zap.Int("total_alerts", totalAlerts))

	return nil
}

// Utility functions

func generateIPsFromCIDR(ipNet *net.IPNet) []string {
	var ips []string
	
	// For large networks, this could be optimized
	ip := ipNet.IP.Mask(ipNet.Mask)
	for ipNet.Contains(ip) {
		ips = append(ips, ip.String())
		inc(ip)
	}
	
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func sampleIPs(ips []string, maxCount int) []string {
	if len(ips) <= maxCount {
		return ips
	}
	
	// Simple sampling - take every nth IP
	step := len(ips) / maxCount
	var sampled []string
	for i := 0; i < len(ips); i += step {
		sampled = append(sampled, ips[i])
		if len(sampled) >= maxCount {
			break
		}
	}
	
	return sampled
}