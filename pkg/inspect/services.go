package inspect

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// DiscoverServices gathers service configuration information
func (i *Inspector) DiscoverServices() (*ServicesInfo, error) {
	logger := otelzap.Ctx(i.rc.Ctx)
	logger.Info("⚙️ Starting services discovery")

	info := &ServicesInfo{}

	// Discover systemd services
	if services, err := i.discoverSystemdServices(); err != nil {
		logger.Warn("⚠️ Failed to discover systemd services", zap.Error(err))
	} else {
		info.SystemdServices = services
		logger.Info("🔧 Discovered systemd services", zap.Int("count", len(services)))
	}

	// Discover Nginx
	if nginx, err := i.discoverNginx(); err == nil && nginx != nil {
		info.Nginx = nginx
		logger.Info("🌐 Discovered Nginx configuration")
	}

	// Discover Apache
	if apache, err := i.discoverApache(); err == nil && apache != nil {
		info.Apache = apache
		logger.Info("🌐 Discovered Apache configuration")
	}

	// Discover Caddy
	if caddy, err := i.discoverCaddy(); err == nil && caddy != nil {
		info.Caddy = caddy
		logger.Info("🌐 Discovered Caddy configuration")
	}

	// Discover PostgreSQL
	if postgres, err := i.discoverPostgreSQL(); err == nil && postgres != nil {
		info.PostgreSQL = postgres
		logger.Info("🗄️ Discovered PostgreSQL configuration")
	}

	// Discover MySQL
	if mysql, err := i.discoverMySQL(); err == nil && mysql != nil {
		info.MySQL = mysql
		logger.Info("🗄️ Discovered MySQL configuration")
	}

	// Discover Redis
	if redis, err := i.discoverRedis(); err == nil && redis != nil {
		info.Redis = redis
		logger.Info("💾 Discovered Redis configuration")
	}

	// Discover HashiCorp tools
	if hashicorp, err := i.discoverHashiCorp(); err == nil && hashicorp != nil {
		info.HashiCorp = hashicorp
		logger.Info("🔧 Discovered HashiCorp tools")
	}

	// Discover Tailscale
	if tailscale, err := i.discoverTailscale(); err == nil && tailscale != nil {
		info.Tailscale = tailscale
		logger.Info("🔐 Discovered Tailscale configuration")
	}

	logger.Info("✅ Services discovery completed")
	return info, nil
}

// discoverSystemdServices discovers running systemd services
func (i *Inspector) discoverSystemdServices() ([]SystemdService, error) {
	var services []SystemdService

	// Get all running services
	output, err := i.runCommand("systemctl", "list-units", "--type=service", "--no-pager", "--no-legend")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		// Parse systemctl output
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		service := SystemdService{
			Name:        fields[0],
			LoadState:   fields[1],
			ActiveState: fields[2],
			SubState:    fields[3],
		}

		// Get description (remaining fields)
		if len(fields) > 4 {
			service.Description = strings.Join(fields[4:], " ")
		}

		// Get service state
		if service.ActiveState == "active" && service.SubState == "running" {
			service.State = "running"
		} else if service.ActiveState == "active" {
			service.State = "active"
		} else {
			service.State = service.ActiveState
		}

		services = append(services, service)
	}

	return services, nil
}

// discoverNginx discovers Nginx configuration
func (i *Inspector) discoverNginx() (*NginxInfo, error) {
	if !i.commandExists("nginx") {
		return nil, fmt.Errorf("nginx not found")
	}

	info := &NginxInfo{}

	// Get version
	if output, err := i.runCommand("nginx", "-v"); err == nil {
		// nginx outputs version to stderr
		info.Version = extractVersion(output)
	} else if output, err := i.runCommand("nginx", "-V"); err == nil {
		info.Version = extractVersion(output)
	}

	// Find config path
	info.ConfigPath = "/etc/nginx/nginx.conf"
	if _, err := os.Stat(info.ConfigPath); os.IsNotExist(err) {
		// Try to find it from nginx -T
		if output, err := i.runCommand("nginx", "-T"); err == nil {
			if match := regexp.MustCompile(`configuration file (.*) test`).FindStringSubmatch(output); len(match) > 1 {
				info.ConfigPath = match[1]
			}
		}
	}

	// Find site configurations
	sitesPath := "/etc/nginx/sites-enabled"
	if files, err := os.ReadDir(sitesPath); err == nil {
		for _, file := range files {
			if !file.IsDir() {
				info.Sites = append(info.Sites, file.Name())
			}
		}
	}

	// Alternative sites location
	if len(info.Sites) == 0 {
		confPath := "/etc/nginx/conf.d"
		if files, err := os.ReadDir(confPath); err == nil {
			for _, file := range files {
				if !file.IsDir() && strings.HasSuffix(file.Name(), ".conf") {
					info.Sites = append(info.Sites, file.Name())
				}
			}
		}
	}

	// Find upstreams (basic detection)
	if output, err := i.runCommand("nginx", "-T"); err == nil {
		upstreamRe := regexp.MustCompile(`upstream\s+(\w+)\s*\{`)
		matches := upstreamRe.FindAllStringSubmatch(output, -1)
		for _, match := range matches {
			if len(match) > 1 {
				info.Upstreams = append(info.Upstreams, match[1])
			}
		}
	}

	return info, nil
}

// discoverApache discovers Apache configuration
func (i *Inspector) discoverApache() (*ApacheInfo, error) {
	// Try different Apache binary names
	apacheBin := ""
	for _, name := range []string{"apache2", "httpd", "apache"} {
		if i.commandExists(name) {
			apacheBin = name
			break
		}
	}

	if apacheBin == "" {
		return nil, fmt.Errorf("apache not found")
	}

	info := &ApacheInfo{}

	// Get version
	if output, err := i.runCommand(apacheBin, "-v"); err == nil {
		info.Version = extractVersion(output)
	}

	// Find config path
	configPaths := []string{
		"/etc/apache2/apache2.conf",
		"/etc/httpd/conf/httpd.conf",
		"/etc/apache2/httpd.conf",
	}
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			info.ConfigPath = path
			break
		}
	}

	// Find site configurations
	sitePaths := []string{
		"/etc/apache2/sites-enabled",
		"/etc/httpd/conf.d",
		"/etc/apache2/conf.d",
	}
	for _, path := range sitePaths {
		if files, err := os.ReadDir(path); err == nil {
			for _, file := range files {
				if !file.IsDir() {
					info.Sites = append(info.Sites, file.Name())
				}
			}
			break
		}
	}

	// Get loaded modules
	if output, err := i.runCommand(apacheBin, "-M"); err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "_module") {
				// Extract module name
				parts := strings.Fields(line)
				if len(parts) > 0 {
					info.Modules = append(info.Modules, parts[0])
				}
			}
		}
	}

	return info, nil
}

// discoverCaddy discovers Caddy configuration
func (i *Inspector) discoverCaddy() (*CaddyInfo, error) {
	if !i.commandExists("caddy") {
		return nil, fmt.Errorf("caddy not found")
	}

	info := &CaddyInfo{}

	// Get version
	if output, err := i.runCommand("caddy", "version"); err == nil {
		info.Version = strings.TrimSpace(output)
	}

	// Find Caddyfile
	caddyfilePaths := []string{
		"/etc/caddy/Caddyfile",
		"/usr/local/etc/caddy/Caddyfile",
		"/opt/caddy/Caddyfile",
	}
	for _, path := range caddyfilePaths {
		if _, err := os.Stat(path); err == nil {
			info.ConfigPath = path
			break
		}
	}

	// Extract sites from Caddyfile
	if info.ConfigPath != "" {
		if content, err := os.ReadFile(info.ConfigPath); err == nil {
			// Simple site extraction - looks for domain patterns
			siteRe := regexp.MustCompile(`^([a-zA-Z0-9.-]+(?::\d+)?)\s*\{`)
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				if match := siteRe.FindStringSubmatch(line); len(match) > 1 {
					info.Sites = append(info.Sites, match[1])
				}
			}
		}
	}

	return info, nil
}

// discoverPostgreSQL discovers PostgreSQL configuration
func (i *Inspector) discoverPostgreSQL() (*PostgreSQLInfo, error) {
	// Check for PostgreSQL
	psqlCmd := ""
	if i.commandExists("psql") {
		psqlCmd = "psql"
	} else if i.commandExists("sudo") {
		// Try with sudo postgres user
		if output, err := i.runCommand("sudo", "-u", "postgres", "psql", "--version"); err == nil && output != "" {
			psqlCmd = "sudo -u postgres psql"
		}
	}

	if psqlCmd == "" {
		return nil, fmt.Errorf("postgresql not found")
	}

	info := &PostgreSQLInfo{
		Port: 5432, // Default port
	}

	// Get version
	if psqlCmd == "psql" {
		if output, err := i.runCommand("psql", "--version"); err == nil {
			info.Version = extractVersion(output)
		}
	} else {
		if output, err := i.runCommand("sudo", "-u", "postgres", "psql", "--version"); err == nil {
			info.Version = extractVersion(output)
		}
	}

	// Find data directory
	dataDirs := []string{
		"/var/lib/postgresql/data",
		"/var/lib/pgsql/data",
		"/usr/local/pgsql/data",
	}
	for _, dir := range dataDirs {
		if _, err := os.Stat(dir); err == nil {
			info.DataDir = dir
			break
		}
	}

	// Get databases (if we have permission)
	var dbOutput string
	var err error
	if psqlCmd == "psql" {
		dbOutput, err = i.runCommand("psql", "-lqt")
	} else {
		dbOutput, err = i.runCommand("sudo", "-u", "postgres", "psql", "-lqt")
	}
	
	if err == nil {
		lines := strings.Split(dbOutput, "\n")
		for _, line := range lines {
			fields := strings.Split(line, "|")
			if len(fields) > 0 {
				dbName := strings.TrimSpace(fields[0])
				if dbName != "" && dbName != "template0" && dbName != "template1" {
					info.Databases = append(info.Databases, dbName)
				}
			}
		}
	}

	// Try to get port from config
	configPaths := []string{
		"/etc/postgresql/*/main/postgresql.conf",
		"/var/lib/pgsql/data/postgresql.conf",
		"/usr/local/pgsql/data/postgresql.conf",
	}
	for _, pattern := range configPaths {
		matches, _ := filepath.Glob(pattern)
		for _, configPath := range matches {
			if content, err := os.ReadFile(configPath); err == nil {
				portRe := regexp.MustCompile(`^\s*port\s*=\s*(\d+)`)
				lines := strings.Split(string(content), "\n")
				for _, line := range lines {
					if match := portRe.FindStringSubmatch(line); len(match) > 1 {
						if port, err := strconv.Atoi(match[1]); err == nil {
							info.Port = port
							break
						}
					}
				}
			}
		}
	}

	return info, nil
}

// discoverMySQL discovers MySQL configuration
func (i *Inspector) discoverMySQL() (*MySQLInfo, error) {
	if !i.commandExists("mysql") {
		return nil, fmt.Errorf("mysql not found")
	}

	info := &MySQLInfo{
		Port: 3306, // Default port
	}

	// Get version
	if output, err := i.runCommand("mysql", "--version"); err == nil {
		info.Version = extractVersion(output)
	}

	// Find data directory
	dataDirs := []string{
		"/var/lib/mysql",
		"/usr/local/mysql/data",
		"/opt/mysql/data",
	}
	for _, dir := range dataDirs {
		if _, err := os.Stat(dir); err == nil {
			info.DataDir = dir
			break
		}
	}

	// Get databases (if we can connect without password)
	if output, err := i.runCommand("mysql", "-e", "SHOW DATABASES;"); err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			dbName := strings.TrimSpace(line)
			if dbName != "" && dbName != "Database" && 
				dbName != "information_schema" && 
				dbName != "mysql" && 
				dbName != "performance_schema" &&
				dbName != "sys" {
				info.Databases = append(info.Databases, dbName)
			}
		}
	}

	return info, nil
}

// discoverRedis discovers Redis configuration
func (i *Inspector) discoverRedis() (*RedisInfo, error) {
	if !i.commandExists("redis-cli") {
		return nil, fmt.Errorf("redis not found")
	}

	info := &RedisInfo{
		Port: 6379, // Default port
	}

	// Get version from server
	if output, err := i.runCommand("redis-cli", "INFO", "server"); err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "redis_version:") {
				info.Version = strings.TrimPrefix(line, "redis_version:")
				info.Version = strings.TrimSpace(info.Version)
			}
		}
	}

	// Get memory usage
	if output, err := i.runCommand("redis-cli", "INFO", "memory"); err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "used_memory_human:") {
				info.Memory = strings.TrimPrefix(line, "used_memory_human:")
				info.Memory = strings.TrimSpace(info.Memory)
			}
		}
	}

	return info, nil
}

// discoverHashiCorp discovers HashiCorp tools
func (i *Inspector) discoverHashiCorp() (*HashiCorpInfo, error) {
	info := &HashiCorpInfo{}
	foundAny := false

	// Check Vault
	if i.commandExists("vault") {
		tool := &HashiCorpTool{}
		if output, err := i.runCommand("vault", "version"); err == nil {
			tool.Version = extractVersion(output)
		}
		
		// Find config
		configPaths := []string{
			"/etc/vault.d/vault.hcl",
			"/etc/vault/vault.hcl",
			"/usr/local/etc/vault/vault.hcl",
		}
		for _, path := range configPaths {
			if _, err := os.Stat(path); err == nil {
				tool.ConfigPath = path
				break
			}
		}

		// Check status
		if output, err := i.runCommand("vault", "status", "-format=json"); err == nil {
			if strings.Contains(output, `"sealed":false`) {
				tool.Status = "unsealed"
			} else if strings.Contains(output, `"sealed":true`) {
				tool.Status = "sealed"
			}
		}

		info.Vault = tool
		foundAny = true
	}

	// Check Consul
	if i.commandExists("consul") {
		tool := &HashiCorpTool{}
		if output, err := i.runCommand("consul", "version"); err == nil {
			tool.Version = extractVersion(output)
		}

		// Find config
		configPaths := []string{
			"/etc/consul.d/consul.hcl",
			"/etc/consul/consul.hcl",
			"/usr/local/etc/consul/consul.hcl",
		}
		for _, path := range configPaths {
			if _, err := os.Stat(path); err == nil {
				tool.ConfigPath = path
				break
			}
		}

		// Check status
		if _, err := i.runCommand("consul", "members"); err == nil {
			tool.Status = "running"
		}

		info.Consul = tool
		foundAny = true
	}

	// Check Nomad
	if i.commandExists("nomad") {
		tool := &HashiCorpTool{}
		if output, err := i.runCommand("nomad", "version"); err == nil {
			tool.Version = extractVersion(output)
		}

		// Find config
		configPaths := []string{
			"/etc/nomad.d/nomad.hcl",
			"/etc/nomad/nomad.hcl",
			"/usr/local/etc/nomad/nomad.hcl",
		}
		for _, path := range configPaths {
			if _, err := os.Stat(path); err == nil {
				tool.ConfigPath = path
				break
			}
		}

		// Check status
		if _, err := i.runCommand("nomad", "server", "members"); err == nil {
			tool.Status = "running"
		}

		info.Nomad = tool
		foundAny = true
	}

	// Check Boundary
	if i.commandExists("boundary") {
		tool := &HashiCorpTool{}
		if output, err := i.runCommand("boundary", "version"); err == nil {
			tool.Version = extractVersion(output)
		}

		// Find config
		configPaths := []string{
			"/etc/boundary.d/boundary.hcl",
			"/etc/boundary/boundary.hcl",
			"/usr/local/etc/boundary/boundary.hcl",
		}
		for _, path := range configPaths {
			if _, err := os.Stat(path); err == nil {
				tool.ConfigPath = path
				break
			}
		}

		info.Boundary = tool
		foundAny = true
	}

	if !foundAny {
		return nil, fmt.Errorf("no HashiCorp tools found")
	}

	return info, nil
}

// discoverTailscale discovers Tailscale configuration
func (i *Inspector) discoverTailscale() (*TailscaleInfo, error) {
	if !i.commandExists("tailscale") {
		return nil, fmt.Errorf("tailscale not found")
	}

	info := &TailscaleInfo{}

	// Get version
	if output, err := i.runCommand("tailscale", "version"); err == nil {
		lines := strings.Split(output, "\n")
		if len(lines) > 0 {
			info.Version = strings.TrimSpace(lines[0])
		}
	}

	// Get status
	if output, err := i.runCommand("tailscale", "status"); err == nil {
		lines := strings.Split(output, "\n")
		if len(lines) > 0 {
			// First line is usually the current node
			fields := strings.Fields(lines[0])
			if len(fields) >= 2 {
				info.IP = fields[0]
				info.Hostname = strings.TrimSuffix(fields[1], "....")
				info.Status = "connected"
			}
		}

		// Parse peers
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				peer := TailscalePeer{
					IP:     fields[0],
					Name:   strings.TrimSuffix(fields[1], "...."),
					OS:     fields[3],
					Online: !strings.Contains(line, "offline"),
				}
				info.Peers = append(info.Peers, peer)
			}
		}
	}

	// Get tailnet name
	if output, err := i.runCommand("tailscale", "status", "--json"); err == nil {
		// Simple extraction without full JSON parsing
		if match := regexp.MustCompile(`"MagicDNSSuffix":\s*"([^"]+)"`).FindStringSubmatch(output); len(match) > 1 {
			info.Tailnet = match[1]
		}
	}

	return info, nil
}

// extractVersion extracts version number from version command output
func extractVersion(output string) string {
	// Common version patterns
	patterns := []string{
		`(\d+\.\d+\.\d+(?:\.\d+)?)`,      // x.y.z or x.y.z.w
		`v(\d+\.\d+\.\d+(?:\.\d+)?)`,     // vx.y.z
		`version\s+(\d+\.\d+\.\d+)`,       // version x.y.z
		`Version:\s*(\d+\.\d+\.\d+)`,      // Version: x.y.z
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if match := re.FindStringSubmatch(output); len(match) > 1 {
			return match[1]
		}
	}

	// If no pattern matches, return the first line trimmed
	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}

	return output
}