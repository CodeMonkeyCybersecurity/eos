/* cmd/hecate/update/config.go */

package update

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

const (
	lastValuesFile = ".hecate.conf"
	confDir        = "conf.d"
)

// loadLastValues loads previously saved values from .hecate.conf.
func loadLastValues() (map[string]string, error) {
	values := make(map[string]string)
	file, err := os.Open(lastValuesFile)
	if err != nil {
		// If the file doesn't exist, simply return an empty map.
		if os.IsNotExist(err) {
			return values, nil
		}
		return values, err
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
		value := strings.TrimSpace(parts[1])
		// Remove surrounding quotes if they exist.
		value = strings.Trim(value, `"`)
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return values, err
	}
	return values, nil
}

// promptInput prompts the user for input with an optional default.
func promptInput(varName, promptMessage, defaultVal string) string {
	reader := bufio.NewReader(os.Stdin)
	for {
		if defaultVal != "" {
			fmt.Printf("%s [%s]: ", promptMessage, defaultVal)
		} else {
			fmt.Printf("%s: ", promptMessage)
		}
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading input:", err)
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

// saveLastValues writes the provided values to the .hecate.conf file.
func saveLastValues(values map[string]string) error {
	file, err := os.Create(lastValuesFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for key, value := range values {
		// Format: KEY="VALUE"
		line := fmt.Sprintf(`%s="%s"`+"\n", key, value)
		_, err := writer.WriteString(line)
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}

// backupFile creates a backup of the file with a timestamp prefix.
func backupFile(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		// If not a regular file, skip backup.
		return nil
	}

	// Create a timestamp in the format YYYYMMDD-HHMMSS.
	timestamp := time.Now().Format("20060102-150405")
	base := filepath.Base(filePath)
	backupFilename := fmt.Sprintf("%s_%s.bak", timestamp, base)
	backupPath := filepath.Join(filepath.Dir(filePath), backupFilename)

	srcFile, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(backupPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		return err
	}
	fmt.Printf("Backup of '%s' created as '%s'.\n", filePath, backupPath)
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
		if err := backupFile(filePath); err != nil {
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

// configCmd is the "config" subcommand for updating conf.d configuration files.
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Update configuration files in conf.d",
	Long:  `Recursively update configuration files in the conf.d directory by replacing placeholder variables.`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()
		log.Info("Running update config command")

		// Display a header for the interactive update.
		fmt.Println("=== Recursive conf.d Variable Updater ===\n")

		// Load previous values if available.
		lastValues, err := loadLastValues()
		if err != nil {
			log.Error("Error loading last values", zap.Error(err))
			fmt.Printf("Error loading last values: %v\n", err)
		}

		// Prompt user for values, using stored defaults if available.
		backendIP := promptInput("BACKEND_IP", "Enter the backend IP address", lastValues["BACKEND_IP"])
		persBackendIP := promptInput("PERS_BACKEND_IP", "Enter the backend IP address for your Persephone backups", lastValues["PERS_BACKEND_IP"])
		delphiBackendIP := promptInput("DELPHI_BACKEND_IP", "Enter the backend IP address for your Delphi install", lastValues["DELPHI_BACKEND_IP"])
		baseDomain := promptInput("BASE_DOMAIN", "Enter the base domain for your services", lastValues["BASE_DOMAIN"])

		// Save the new values for future runs.
		newValues := map[string]string{
			"BACKEND_IP":        backendIP,
			"PERS_BACKEND_IP":   persBackendIP,
			"DELPHI_BACKEND_IP": delphiBackendIP,
			"BASE_DOMAIN":       baseDomain,
		}
		if err := saveLastValues(newValues); err != nil {
			log.Error("Error saving new values", zap.Error(err))
			fmt.Printf("Error saving new values: %v\n", err)
		}

		// Ensure the conf.d directory exists.
		if info, err := os.Stat(confDir); err != nil || !info.IsDir() {
			errMsg := fmt.Sprintf("Error: Directory '%s' not found in the current directory.", confDir)
			log.Error(errMsg)
			fmt.Println(errMsg)
			return fmt.Errorf(errMsg)
		}

		// Process all .conf files recursively in the conf.d directory.
		processConfDirectory(confDir, backendIP, persBackendIP, delphiBackendIP, baseDomain)

		fmt.Println("\nDone updating configuration files in the conf.d directory.")
		return nil
	}),
}

func init() {
	// Attach the config subcommand to the parent update command.
	UpdateCmd.AddCommand(configCmd)
}
