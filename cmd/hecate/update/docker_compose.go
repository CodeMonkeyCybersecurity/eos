/* cmd/hecate/update/docker_compose.go */

package update

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

const (
	lastValuesFile    = ".hecate.conf"
	dockerComposeFile = "docker-compose.yml"
)

// AppOption holds the app name and its corresponding config filename.
type AppOption struct {
	Name string
	Conf string
}

// appOptions maps option numbers to app details.
var appOptions = map[string]AppOption{
	"1":  {"Static website", "base.conf"},
	"2":  {"Wazuh", "delphi.conf"},
	"3":  {"Mattermost", "collaborate.conf"},
	"4":  {"Nextcloud", "cloud.conf"},
	"5":  {"Mailcow", "mailcow.conf"},
	"6":  {"Jenkins", "jenkins.conf"},
	"7":  {"Grafana", "observe.conf"},
	"8":  {"Umami", "analytics.conf"},
	"9":  {"MinIO", "s3.conf"},
	"10": {"Wiki.js", "wiki.conf"},
	"11": {"ERPNext", "erp.conf"},
	"12": {"Jellyfin", "jellyfin.conf"},
	"13": {"Persephone", "persephone.conf"},
}

// supportedApps maps the app’s lowercase name to a list of port markers.
var supportedApps = map[string][]string{
	"wazuh":     {"1515", "1514", "55000"},
	"mailcow":   {"25", "587", "465", "110", "995", "143", "993"},
	"nextcloud": {"3478"},
}

// loadLastValues reads key=value pairs from lastValuesFile.
func loadLastValues() map[string]string {
	values := make(map[string]string)
	file, err := os.Open(lastValuesFile)
	if err != nil {
		return values // File may not exist; return an empty map.
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"")
		values[key] = value
	}
	return values
}

// saveLastValues writes key=value pairs into lastValuesFile.
func saveLastValues(values map[string]string) error {
	file, err := os.Create(lastValuesFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for key, val := range values {
		line := fmt.Sprintf(`%s="%s"`+"\n", key, val)
		_, err := writer.WriteString(line)
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}

// backupFile creates a timestamped backup of the specified file.
func backupFile(filePath string) error {
	if _, err := os.Stat(filePath); err == nil {
		timestamp := time.Now().Format("20060102-150405")
		base := filepath.Base(filePath)
		backupPath := filepath.Join(filepath.Dir(filePath), fmt.Sprintf("%s_%s.bak", timestamp, base))
		content, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		if err = os.WriteFile(backupPath, content, 0644); err != nil {
			return err
		}
		fmt.Printf("Backup of '%s' created as '%s'.\n", filePath, backupPath)
	}
	return nil
}

// displayOptions prints the available app options.
func displayOptions() {
	fmt.Println("Available EOS backend web apps:")
	var keys []int
	for k := range appOptions {
		var num int
		fmt.Sscanf(k, "%d", &num)
		keys = append(keys, num)
	}
	sort.Ints(keys)
	for _, num := range keys {
		keyStr := fmt.Sprintf("%d", num)
		opt := appOptions[keyStr]
		fmt.Printf("  %s. %s  -> %s\n", keyStr, opt.Name, opt.Conf)
	}
}

// getUserSelection prompts the user to enter a comma-separated list of options.
func getUserSelection(defaultSelection string) (map[string]bool, string) {
	reader := bufio.NewReader(os.Stdin)
	for {
		prompt := "Enter the numbers (comma-separated) of the apps you want enabled (or type 'all' for all supported)"
		if defaultSelection != "" {
			prompt += fmt.Sprintf(" [default: %s]", defaultSelection)
		}
		prompt += ": "
		fmt.Print(prompt)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "" && defaultSelection != "" {
			input = defaultSelection
		}
		if strings.ToLower(input) == "all" {
			set := make(map[string]bool)
			for key := range supportedApps {
				set[key] = true
			}
			return set, "all"
		}
		tokens := strings.Split(input, ",")
		chosen := make(map[string]bool)
		valid := true
		for _, token := range tokens {
			token = strings.TrimSpace(token)
			opt, exists := appOptions[token]
			if !exists {
				fmt.Printf("Invalid option: %s\n", token)
				valid = false
				break
			}
			key := strings.ToLower(opt.Name)
			if _, ok := supportedApps[key]; ok {
				chosen[key] = true
			}
		}
		if valid && len(chosen) > 0 {
			return chosen, input
		}
		fmt.Println("Please enter a valid comma-separated list of options corresponding to supported apps.")
	}
}

// updateComposeFile reads docker-compose.yml and uncomments lines for selected apps.
func updateComposeFile(selectedApps map[string]bool) error {
	data, err := os.ReadFile(dockerComposeFile)
	if err != nil {
		return fmt.Errorf("Error: %s not found", dockerComposeFile)
	}

	lines := strings.Split(string(data), "\n")
	var newLines []string
	// Regex to remove a leading '#' before '-'
	re := regexp.MustCompile(`^(\s*)#\s*(-)`)
	for _, line := range lines {
		modifiedLine := line
		for app, markers := range supportedApps {
			if selectedApps[app] {
				for _, marker := range markers {
					if strings.Contains(line, marker) {
						modifiedLine = re.ReplaceAllString(line, "$1$2")
						break
					}
				}
			}
		}
		newLines = append(newLines, modifiedLine)
	}

	// Backup the original docker-compose file.
	if err = backupFile(dockerComposeFile); err != nil {
		return err
	}

	output := strings.Join(newLines, "\n")
	if err = os.WriteFile(dockerComposeFile, []byte(output), 0644); err != nil {
		return err
	}

	var apps []string
	for app := range selectedApps {
		apps = append(apps, app)
	}
	fmt.Printf("Updated %s for apps: %s\n", dockerComposeFile, strings.Join(apps, ", "))
	return nil
}

// dockerComposeCmd is the subcommand that updates the docker-compose file.
var dockerComposeCmd = &cobra.Command{
	Use:   "docker-compose",
	Short: "Update the docker-compose file based on selected EOS apps",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()
		lastValues := loadLastValues()
		selectedApps := make(map[string]bool)
		var selectionStr string

		// Command-line mode: if arguments are provided.
		if len(args) > 0 {
			for _, arg := range args {
				lower := strings.ToLower(arg)
				if _, ok := supportedApps[lower]; ok {
					selectedApps[lower] = true
				}
			}
			if len(selectedApps) == 0 {
				log.Error("No supported apps found in the command-line arguments.")
				return fmt.Errorf("no supported apps found in the command-line arguments")
			}
			var keys []string
			for k := range selectedApps {
				keys = append(keys, k)
			}
			selectionStr = strings.Join(keys, ", ")
		} else {
			// Interactive mode.
			displayOptions()
			defaultSelection := lastValues["APPS_SELECTION"]
			var sel string
			selectedApps, sel = getUserSelection(defaultSelection)
			selectionStr = sel
			lastValues["APPS_SELECTION"] = selectionStr
			if err := saveLastValues(lastValues); err != nil {
				log.Error("Error saving last values.", zap.Error(err))
				return err
			}
		}
		if err := updateComposeFile(selectedApps); err != nil {
			log.Error("Error updating docker-compose file.", zap.Error(err))
			return err
		}
		return nil
	}),
}
