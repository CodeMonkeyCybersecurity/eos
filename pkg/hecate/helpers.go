/* pkg/hecate/helper.go */

package hecate

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"go.uber.org/zap"
)

// loadLastValues reads key="value" pairs from LastValuesFile and returns them as a map.
func LoadLastValues() map[string]string {
	values := make(map[string]string)
	file, err := os.Open(hecate.LastValuesFile)
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
func PromptInput(varName, promptMessage, defaultVal string, reader *bufio.Reader) string {
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

// saveLastValues writes the provided map to LastValuesFile in key="value" format.
func SaveLastValues(values map[string]string) {
	file, err := os.Create(LastValuesFile)
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
func BackupFile(filepathStr string) {
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
func DisplayOptions() {
	fmt.Println("Available EOS backend web apps:")
	// To display options in order, first sort the keys numerically.
	var keys []int
	keyMap := make(map[int]string)
	for keyStr := range hecate.AppsSelection {
		var num int
		fmt.Sscanf(keyStr, "%d", &num)
		keys = append(keys, num)
		keyMap[num] = keyStr
	}
	sort.Ints(keys)
	for _, num := range keys {
		keyStr := keyMap[num]
		app := hecate.AppsSelection[keyStr]
		fmt.Printf("  %d. %s  -> %s\n", num, app.AppName, app.ConfFile)
	}
}

// getUserSelection prompts the user to enter a comma-separated list of option numbers.
// It returns a set (map with bool value) of allowed configuration filenames and the raw selection string.
func GetUserSelection(defaultSelection string, reader *bufio.Reader) (map[string]bool, string) {
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
			for _, app := range hecate.AppsSelection {
				allowed[app.ConfFile] = true
			}
			return allowed, "all"
		}

		allowed := make(map[string]bool)
		valid := true
		tokens := strings.Split(input, ",")
		for _, token := range tokens {
			token = strings.TrimSpace(token)
			if app, ok := hecate.AppsSelection[token]; ok {
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

// updateComposeFile reads docker-compose.yml and uncomments lines for selected apps.
func UpdateComposeFile(selectedApps map[string]bool) error {
	data, err := os.ReadFile(hecate.DockerComposeFile)
	if err != nil {
		return fmt.Errorf("Error: %s not found", hecate.hecate.DockerComposeFile)
	}

	lines := strings.Split(string(data), "\n")
	var newLines []string
	// Regex to remove a leading '#' before '-'
	re := regexp.MustCompile(`^(\s*)#\s*(-)`)
	for _, line := range lines {
		modifiedLine := line
		for app, markers := range hecate.supportedApps {
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
	if err = BackupFile(hecate.DockerComposeFile); err != nil {
		return err
	}

	output := strings.Join(newLines, "\n")
	if err = os.WriteFile(hecate.DockerComposeFile, []byte(output), 0644); err != nil {
		return err
	}

	var apps []string
	for app := range selectedApps {
		apps = append(apps, app)
	}
	fmt.Printf("Updated %s for apps: %s\n", hecate.DockerComposeFile, strings.Join(apps, ", "))
	return nil
}

// updateFile replaces the placeholder variables in a single file.
func updateFile(filePath, BACKEND_IP, PERS_BACKEND_IP, DELPHI_BACKEND_IP, BASE_DOMAIN string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", filePath, err)
		return
	}
	content := string(data)
	newContent := strings.ReplaceAll(content, "${BACKEND_IP}", BACKEND_IP)
	newContent = strings.ReplaceAll(newContent, "${PERS_BACKEND_IP}", PERS_BACKEND_IP)
	newContent = strings.ReplaceAll(newContent, "${DELPHI_BACKEND_IP}", DELPHI_BACKEND_IP)
	newContent = strings.ReplaceAll(newContent, "${BASE_DOMAIN}", BASE_DOMAIN)

	if newContent != content {
		if err := BackupFile(filePath); err != nil {
			fmt.Printf("Error creating backup for %s: %v\n", filePath, err)
		}
		err = os.WriteFile(filePath, []byte(newContent), 0644)
		if err != nil {
			fmt.Printf("Error writing %s: %v\n", filePath, err)
		} else {
			fmt.Printf("Updated %s\n", filePath)
		}
	}
}

// processConfDirectory recursively processes all .conf files in the specified directory.
func processConfDirectory(directory, BACKEND_IP, PERS_BACKEND_IP, DELPHI_BACKEND_IP, BASE_DOMAIN string) {
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("Error accessing path %s: %v\n", path, err)
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".conf") {
			updateFile(path, BACKEND_IP, PERS_BACKEND_IP, DELPHI_BACKEND_IP, BASE_DOMAIN)
		}
		return nil
	})
	if err != nil {
		fmt.Printf("Error processing directory %s: %v\n", directory, err)
	}
}
