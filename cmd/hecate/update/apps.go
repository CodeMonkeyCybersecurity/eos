/* cmd/hecate/update/apps.go */

package update

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// Constants for file locations.
const (
	lastValuesFile = ".hecate.conf"
	confDir        = "conf.d"
)

// AppSelection holds an app name and its configuration file.
type AppSelection struct {
	AppName  string
	ConfFile string
}

// Global mapping from option number to its corresponding AppSelection.
var appsSelection = map[string]AppSelection{
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

// loadLastValues reads key="value" pairs from lastValuesFile and returns them as a map.
func loadLastValues() map[string]string {
	values := make(map[string]string)
	file, err := os.Open(lastValuesFile)
	if err != nil {
		// If the file doesn't exist, return an empty map.
		return values
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines or those without "=".
		if line == "" || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		// Remove surrounding quotes from the value.
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		logger.GetLogger().Error("Error reading last values", zap.Error(err))
	}
	return values
}

// promptInput asks the user for input until a non-empty string is provided (unless a default exists).
func promptInput(varName, promptMessage, defaultVal string, reader *bufio.Reader) string {
	for {
		if defaultVal != "" {
			fmt.Printf("%s [%s]: ", promptMessage, defaultVal)
		} else {
			fmt.Printf("%s: ", promptMessage)
		}
		input, err := reader.ReadString('\n')
		if err != nil {
			logger.GetLogger().Error("Error reading input", zap.Error(err))
			continue
		}
		input = strings.TrimSpace(input)
		if input == "" && defaultVal != "" {
			return defaultVal
		} else if input != "" {
			return input
		} else {
			fmt.Printf("Error: %s cannot be empty. Please enter a valid value.\n", varName)
		}
	}
}

// saveLastValues writes the provided map to lastValuesFile in key="value" format.
func saveLastValues(values map[string]string) {
	file, err := os.Create(lastValuesFile)
	if err != nil {
		logger.GetLogger().Fatal("Unable to save values", zap.Error(err))
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for key, value := range values {
		// Write each line as: key="value"
		_, err := writer.WriteString(fmt.Sprintf("%s=\"%s\"\n", key, value))
		if err != nil {
			logger.GetLogger().Fatal("Error writing to file", zap.Error(err))
		}
	}
	writer.Flush()
}

// backupFile creates a backup of the provided file by copying it to a new file with a timestamp.
func backupFile(filepathStr string) {
	if info, err := os.Stat(filepathStr); err == nil && !info.IsDir() {
		timestamp := time.Now().Format("20060102-150405")
		baseName := filepath.Base(filepathStr)
		dirName := filepath.Dir(filepathStr)
		backupName := fmt.Sprintf("%s_%s.bak", timestamp, baseName)
		backupPath := filepath.Join(dirName, backupName)

		src, err := os.Open(filepathStr)
		if err != nil {
			logger.GetLogger().Fatal("Error opening source file for backup", zap.Error(err))
		}
		defer src.Close()

		dest, err := os.Create(backupPath)
		if err != nil {
			logger.GetLogger().Fatal("Error creating backup file", zap.Error(err))
		}
		defer dest.Close()

		_, err = io.Copy(dest, src)
		if err != nil {
			logger.GetLogger().Fatal("Error copying to backup file", zap.Error(err))
		}
		fmt.Printf("Backup of '%s' created as '%s'.\n", filepathStr, backupPath)
	}
}

// displayOptions prints the available EOS backend web apps.
func displayOptions() {
	fmt.Println("Available EOS backend web apps:")
	// To display options in order, first sort the keys numerically.
	var keys []int
	keyMap := make(map[int]string)
	for keyStr := range appsSelection {
		var num int
		fmt.Sscanf(keyStr, "%d", &num)
		keys = append(keys, num)
		keyMap[num] = keyStr
	}
	sort.Ints(keys)
	for _, num := range keys {
		keyStr := keyMap[num]
		app := appsSelection[keyStr]
		fmt.Printf("  %d. %s  -> %s\n", num, app.AppName, app.ConfFile)
	}
}

// getUserSelection prompts the user to enter a comma-separated list of option numbers.
// It returns a set (map with bool value) of allowed configuration filenames and the raw selection string.
func getUserSelection(defaultSelection string, reader *bufio.Reader) (map[string]bool, string) {
	for {
		promptMsg := "Enter the numbers (comma-separated) of the apps you want enabled (or type 'all' for all)"
		if defaultSelection != "" {
			promptMsg += fmt.Sprintf(" [default: %s]", defaultSelection)
		}
		promptMsg += ": "

		fmt.Print(promptMsg)
		input, err := reader.ReadString('\n')
		if err != nil {
			logger.GetLogger().Fatal("Error reading input", zap.Error(err))
		}
		input = strings.TrimSpace(input)
		// Use the default if nothing was entered.
		if input == "" && defaultSelection != "" {
			input = defaultSelection
		}

		// If user entered "all", add all configuration filenames.
		if strings.ToLower(input) == "all" {
			allowed := make(map[string]bool)
			for _, app := range appsSelection {
				allowed[app.ConfFile] = true
			}
			return allowed, "all"
		}

		allowed := make(map[string]bool)
		valid := true
		tokens := strings.Split(input, ",")
		for _, token := range tokens {
			token = strings.TrimSpace(token)
			if app, ok := appsSelection[token]; ok {
				allowed[app.ConfFile] = true
			} else {
				fmt.Printf("Invalid option: %s\n", token)
				valid = false
				break
			}
		}
		if valid && len(allowed) > 0 {
			return allowed, input
		}
		fmt.Println("Please enter a valid comma-separated list of options.")
		// Loop again if invalid.
	}
}

// removeUnwantedConfFiles walks through the confDir and removes any .conf file
// whose base name is not in the allowedFiles set.
func removeUnwantedConfFiles(allowedFiles map[string]bool) {
	info, err := os.Stat(confDir)
	if err != nil || !info.IsDir() {
		fmt.Printf("Error: Directory '%s' not found.\n", confDir)
		return
	}

	var removedFiles []string
	// Recursively walk the configuration directory.
	err = filepath.Walk(confDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip files with errors.
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".conf") {
			if !allowedFiles[info.Name()] {
				// Try to remove the file.
				err := os.Remove(path)
				if err != nil {
					fmt.Printf("Error removing %s: %v\n", path, err)
				} else {
					removedFiles = append(removedFiles, path)
					fmt.Printf("Removed: %s\n", path)
				}
			}
		}
		return nil
	})
	if err != nil {
		logger.GetLogger().Fatal("Error walking the directory", zap.Error(err))
	}

	if len(removedFiles) == 0 {
		fmt.Println("No configuration files were removed.")
	} else {
		fmt.Println("\nCleanup complete. The following files were removed:")
		for _, f := range removedFiles {
			fmt.Printf(" - %s\n", f)
		}
	}
}

// appsCmd is the "apps" subcommand for updating enabled applications.
var appsCmd = &cobra.Command{
	Use:   "apps",
	Short: "Update enabled applications in the conf.d directory",
	Long:  `Select and keep configuration files for enabled EOS backend web apps while removing others.`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()
		log.Info("Running update apps command")

		fmt.Println("=== EOS Backend Web Apps Selector ===\n")
		reader := bufio.NewReader(os.Stdin)

		// Load previous values from the configuration file.
		lastValues := loadLastValues()
		defaultApps := lastValues["APPS_SELECTION"]

		// Display available apps.
		displayOptions()

		// Prompt for a selection.
		allowedFiles, selectionStr := getUserSelection(defaultApps, reader)

		// Always add essential configuration files.
		essentialFiles := []string{"http.conf", "stream.conf", "fallback.conf"}
		for _, file := range essentialFiles {
			allowedFiles[file] = true
		}

		fmt.Println("\nYou have selected the following configuration files to keep:")
		// Print the allowed files list.
		for file := range allowedFiles {
			// Check if the file is essential.
			if file == "http.conf" || file == "stream.conf" || file == "fallback.conf" {
				fmt.Printf(" - Essential file: %s\n", file)
			} else {
				// Try to find the corresponding app name.
				var appName string
				for _, app := range appsSelection {
					if app.ConfFile == file {
						appName = app.AppName
						break
					}
				}
				fmt.Printf(" - %s (%s)\n", appName, file)
			}
		}

		fmt.Println("\nNow scanning the conf.d directory and removing files not in your selection...")
		removeUnwantedConfFiles(allowedFiles)

		// Save the selection back to the last values file.
		lastValues["APPS_SELECTION"] = selectionStr
		saveLastValues(lastValues)

		fmt.Println("\nUpdate complete.")
		return nil
	}),
}

func init() {
	// Attach the apps subcommand to the parent update command.
	UpdateCmd.AddCommand(appsCmd)
}
