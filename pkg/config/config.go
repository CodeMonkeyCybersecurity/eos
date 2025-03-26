package config

import (
	"bufio"

	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"eos/pkg/logger"

	"go.uber.org/zap"
)

//
// ---------------------------- LOGGER ---------------------------- //

var log = logger.L()

//
// ---------------------------- CONSTANTS ---------------------------- //

const (
	// Delphi & Install Paths
	VenvPath         = "/opt/delphi_venv"
	DockerListener   = "/var/ossec/wodles/docker/DockerListener"
	UmamiDir         = "/opt/umami"
	JenkinsDir       = "/opt/jenkins"
	ZabbixDir        = "/opt/zabbix"
	ZabbixComposeYML = "/opt/zabbix/zabbix-docker-compose.yml"

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
	log.Info("Retrieving supported app names")
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
	log.Info("Displaying available Hecate backend web apps")
	log.Info("Sorted app options", zap.Ints("sortedApps", sortedApps))
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
	log.Info("Searching for app by option", zap.String("option", option))
	for _, app := range Apps {
		if app.Option == option {
			log.Info("App found", zap.String("appName", app.Name))
			return app, true
		}
	}
	log.Warn("App not found", zap.String("option", option))
	return App{}, false
}

func GetUserSelection(defaultSelection string) (map[string]App, string) {
	reader := bufio.NewReader(os.Stdin)
	promptMsg := "Enter the numbers (comma-separated) of the apps you want enabled (or type 'all' for all supported)"
	if defaultSelection != "" {
		promptMsg += fmt.Sprintf(" [default: %s]", defaultSelection)
	}
	promptMsg += ": "
	log.Info("Prompting user for app selection", zap.String("message", promptMsg))
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
			log.Warn("Invalid option selected", zap.String("option", token))
			fmt.Printf("Invalid option: %s\n", token)
			return GetUserSelection(defaultSelection)
		}
		selectedApps[strings.ToLower(app.Name)] = app
	}
	if len(selectedApps) == 0 {
		log.Warn("No valid options selected")
		fmt.Println("No valid options selected.")
		return GetUserSelection(defaultSelection)
	}
	log.Info("User selection made", zap.String("selection", selection))
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

	log.Info("Loading configuration from file", zap.String("file", LastValuesFile))

	if _, err := os.Stat(LastValuesFile); err == nil {
		f, err := os.Open(LastValuesFile)
		if err != nil {
			log.Error("Unable to open configuration file", zap.String("file", LastValuesFile), zap.Error(err))
			return nil, fmt.Errorf("unable to open %s: %w", LastValuesFile, err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "BASE_DOMAIN="):
				cfg.BaseDomain = strings.TrimSpace(strings.TrimPrefix(line, "BASE_DOMAIN="))
				log.Info("Found Base Domain", zap.String("baseDomain", cfg.BaseDomain))
			case strings.HasPrefix(line, "backendIP="):
				cfg.BackendIP = strings.TrimSpace(strings.TrimPrefix(line, "backendIP="))
				log.Info("Found Backend IP", zap.String("backendIP", cfg.BackendIP))
			case strings.HasPrefix(line, "SUBDOMAIN="):
				cfg.Subdomain = strings.TrimSpace(strings.TrimPrefix(line, "SUBDOMAIN="))
				log.Info("Found Subdomain", zap.String("subdomain", cfg.Subdomain))
			case strings.HasPrefix(line, "EMAIL="):
				cfg.Email = strings.TrimSpace(strings.TrimPrefix(line, "EMAIL="))
				log.Info("Found Email", zap.String("email", cfg.Email))
			}
		}
		if err := scanner.Err(); err != nil {
			log.Error("Error reading configuration file", zap.Error(err))
			return nil, fmt.Errorf("error reading %s: %w", LastValuesFile, err)
		}
	}

	// Handle missing configuration values and log the prompts
	if cfg.Subdomain == "" && defaultSubdomain != "" {
		cfg.Subdomain = defaultSubdomain
		log.Info("No subdomain found, defaulting to", zap.String("subdomain", defaultSubdomain))
	}

	log.Info("Current configuration", zap.String("BaseDomain", cfg.BaseDomain), zap.String("BackendIP", cfg.BackendIP), zap.String("Subdomain", cfg.Subdomain), zap.String("Email", cfg.Email))

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
		log.Warn("Missing required configuration fields", zap.Strings("missingFields", missing))
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
		log.Error("Failed to write configuration file", zap.String("file", LastValuesFile), zap.Error(err))
		return nil, fmt.Errorf("failed to write %s: %w", LastValuesFile, err)
	}

	log.Info("Configuration successfully loaded and saved", zap.String("file", LastValuesFile))

	return cfg, nil
}

func prompt(message string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(message)
	text, _ := reader.ReadString('\n')
	userInput := strings.TrimSpace(text)

	// Log the user input action, but avoid logging sensitive information.
	log.Info("Prompted user", zap.String("message", message), zap.String("userInput", userInput))

	return userInput
}

//func yesOrNo(message string) bool {
//	response := prompt(message)
//	if response == "" {
//		return true
//	}
//	response = strings.ToLower(response)
//	return response == "y" || response == "yes"
//}
