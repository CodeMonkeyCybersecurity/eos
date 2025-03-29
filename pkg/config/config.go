// pkg/config/config.go

package config

import (
	"bufio"

	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

//
// ---------------------------- CONSTANTS ---------------------------- //

const (
	// Delphi Paths
	VenvPath       = "/opt/delphi_venv"
	DockerListener = "/var/ossec/wodles/docker/DockerListener"

	// Install Paths
	UmamiDir   = "/opt/umami"
	JenkinsDir = "/opt/jenkins"
	ZabbixDir  = "/opt/zabbix"
	HeraDir    = "/opt/hera"

	JenkinsComposeYML = JenkinsDir + "/jenkins-docker-compose.yml"
	UmamiComposeYML   = UmamiDir + "/umami-docker-compose.yml"
	ZabbixComposeYML  = ZabbixDir + "/zabbix-docker-compose.yml"
	HeraComposeYML    = HeraDir + "/hera-docker-compose.yml"

	// Treecat preview
	MaxPreviewSize  = 5 * 1024
	MaxPreviewLines = 100

	// Hecate defaults
	LastValuesFile    = ".hecate.conf"
	DefaultComposeYML = "docker-compose.yml"
	DefaultCertsDir   = "certs"
	DefaultConfDir    = "conf.d"
	AssetsPath        = "assets"
	NginxConfPath     = "/etc/nginx/conf.d/"
	NginxStreamPath   = "/etc/nginx/stream.d/"
	DockerNetworkName = "arachne-net"
	DockerIPv4Subnet  = "10.1.0.0/16"
	DockerIPv6Subnet  = "fd42:1a2b:3c4d:5e6f::/64"
	DefaultConfigPath = "./config/default.yaml"
	AssetServerPath   = "assets/servers"
	AssetStreamPath   = "assets/stream"
)

var DefaultMarkers = []string{"80", "443"}

func CombineMarkers(additional ...string) []string {
	return append(DefaultMarkers, additional...)
}

//
// ---------------------------- APP DEFINITIONS ---------------------------- //

type App struct {
	Option   string
	Name     string
	ConfFile string
	Markers  []string
}

var Apps = []App{
	{"1", "Static website", "base.conf", DefaultMarkers},
	{"2", "Wazuh", "delphi.conf", CombineMarkers("1515", "1514", "55000")},
	{"3", "Mattermost", "collaborate.conf", DefaultMarkers},
	{"4", "Nextcloud", "cloud.conf", CombineMarkers("3478", "coturn:")},
	{"5", "Mailcow", "mailcow.conf", CombineMarkers("25", "587", "465", "110", "995", "143", "993")},
	{"6", "Jenkins", "jenkins.conf", DefaultMarkers},
	{"7", "Grafana", "observe.conf", DefaultMarkers},
	{"8", "Umami", "analytics.conf", DefaultMarkers},
	{"9", "MinIO", "s3.conf", DefaultMarkers},
	{"10", "Wiki.js", "wiki.conf", DefaultMarkers},
	{"11", "ERPNext", "erp.conf", DefaultMarkers},
	{"12", "Jellyfin", "jellyfin.conf", DefaultMarkers},
	{"13", "Persephone", "persephone.conf", DefaultMarkers},
}

func GetSupportedAppNames() []string {
	var names []string
	for _, app := range Apps {
		names = append(names, strings.ToLower(app.Name))
	}
	return names
}

func DisplayOptions() {
	fmt.Println("Available Hecate backend web apps:")
	var sortedApps []int
	for _, app := range Apps {
		if num, err := strconv.Atoi(app.Option); err == nil {
			sortedApps = append(sortedApps, num)
		}
	}
	sort.Ints(sortedApps)
	for _, num := range sortedApps {
		for _, app := range Apps {
			if app.Option == strconv.Itoa(num) {
				fmt.Printf("  %s. %s -> %s\n", app.Option, app.Name, app.ConfFile)
				break
			}
		}
	}
}

func GetAppByOption(option string) (App, bool) {
	for _, app := range Apps {
		if app.Option == option {
			return app, true
		}
	}
	return App{}, false
}

func GetUserSelection(defaultSelection string) (map[string]App, string) {
	reader := bufio.NewReader(os.Stdin)
	promptMsg := "Enter the numbers (comma-separated) of the apps you want enabled (or type 'all' for all supported)"
	if defaultSelection != "" {
		promptMsg += fmt.Sprintf(" [default: %s]", defaultSelection)
	}
	promptMsg += ": "

	fmt.Print(promptMsg)
	selection, _ := reader.ReadString('\n')
	selection = strings.TrimSpace(selection)
	if selection == "" && defaultSelection != "" {
		selection = defaultSelection
	}

	selectedApps := make(map[string]App)
	if strings.ToLower(selection) == "all" {
		for _, app := range Apps {
			selectedApps[strings.ToLower(app.Name)] = app
		}
		return selectedApps, "all"
	}

	parts := strings.Split(selection, ",")
	for _, token := range parts {
		token = strings.TrimSpace(token)
		app, ok := GetAppByOption(token)
		if !ok {

			fmt.Printf("Invalid option: %s\n", token)
			return GetUserSelection(defaultSelection)
		}
		selectedApps[strings.ToLower(app.Name)] = app
	}
	if len(selectedApps) == 0 {
		fmt.Println("No valid options selected.")
		return GetUserSelection(defaultSelection)
	}
	return selectedApps, selection
}

//
// ---------------------------- HECATE CONFIGURATION ---------------------------- //

type HecateConfig struct {
	BaseDomain string
	BackendIP  string
	Subdomain  string
	Email      string
}

func LoadConfig(defaultSubdomain string) (*HecateConfig, error) {
	cfg := &HecateConfig{}

	if _, err := os.Stat(LastValuesFile); err == nil {
		f, err := os.Open(LastValuesFile)
		if err != nil {

			return nil, fmt.Errorf("unable to open %s: %w", LastValuesFile, err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "BASE_DOMAIN="):
				cfg.BaseDomain = strings.TrimSpace(strings.TrimPrefix(line, "BASE_DOMAIN="))

			case strings.HasPrefix(line, "backendIP="):
				cfg.BackendIP = strings.TrimSpace(strings.TrimPrefix(line, "backendIP="))

			case strings.HasPrefix(line, "SUBDOMAIN="):
				cfg.Subdomain = strings.TrimSpace(strings.TrimPrefix(line, "SUBDOMAIN="))

			case strings.HasPrefix(line, "EMAIL="):
				cfg.Email = strings.TrimSpace(strings.TrimPrefix(line, "EMAIL="))

			}
		}
		if err := scanner.Err(); err != nil {

			return nil, fmt.Errorf("error reading %s: %w", LastValuesFile, err)
		}
	}

	// Handle missing configuration values and log the prompts
	if cfg.Subdomain == "" && defaultSubdomain != "" {
		cfg.Subdomain = defaultSubdomain

	}

	// Check if there are missing fields and log them
	missing := []string{}
	if cfg.BaseDomain == "" {
		missing = append(missing, "Base Domain")
	}
	if cfg.BackendIP == "" {
		missing = append(missing, "Backend IP")
	}
	if cfg.Email == "" {
		missing = append(missing, "Email")
	}
	if len(missing) > 0 {

		fmt.Printf("The following fields need to be set: %s\n", strings.Join(missing, ", "))
		if cfg.BaseDomain == "" {
			cfg.BaseDomain = prompt("Please enter the Base Domain (e.g., example.com): ")
		}
		if cfg.BackendIP == "" {
			cfg.BackendIP = prompt("Please enter the Backend IP (e.g., 192.168.1.100): ")
		}
		if cfg.Email == "" {
			cfg.Email = prompt("Please enter the email address for certificate requests (e.g., admin@example.com): ")
		}
	}

	// Log when configuration is written
	content := fmt.Sprintf("BASE_DOMAIN=%s\nbackendIP=%s\nSUBDOMAIN=%s\nEMAIL=%s\n",
		cfg.BaseDomain, cfg.BackendIP, cfg.Subdomain, cfg.Email)
	if err := os.WriteFile(LastValuesFile, []byte(content), 0644); err != nil {

		return nil, fmt.Errorf("failed to write %s: %w", LastValuesFile, err)
	}

	return cfg, nil
}

func prompt(message string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(message)
	text, _ := reader.ReadString('\n')
	userInput := strings.TrimSpace(text)

	// Log the user input action, but avoid logging sensitive information.

	return userInput
}
