package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// configFilename is where we store the last-used values.
const configFilename = ".wazuh.api.conf"

// loadConfig reads key="value" lines into a map.
func loadConfig(filename string) (map[string]string, error) {
	config := make(map[string]string)
	file, err := os.Open(filename)
	if err != nil {
		return config, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// skip empty lines or comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := parts[0]
			// remove quotes if present
			val := strings.Trim(parts[1], `"`)
			config[key] = val
		}
	}
	return config, scanner.Err()
}

// promptInput prompts the user with a message and optional default value.
func promptInput(varName, promptMessage, defaultVal string) string {
	reader := bufio.NewReader(os.Stdin)
	for {
		if defaultVal != "" {
			fmt.Printf("%s [%s]: ", promptMessage, defaultVal)
		} else {
			fmt.Printf("%s: ", promptMessage)
		}
		input, _ := reader.ReadString('\n')
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

func main() {
	fmt.Println("")
	fmt.Println("=============")
	fmt.Println("  CHECK API  ")
	fmt.Println("=============")

	// load previous configuration if available
	config := make(map[string]string)
	if _, err := os.Stat(configFilename); err == nil {
		if loaded, err := loadConfig(configFilename); err == nil {
			config = loaded
		} else {
			fmt.Printf("Warning: could not load config file: %v\n", err)
		}
	}

	fmt.Println("")
	fmt.Println("=== NGINX Configuration Generator ===")

	// prompt for values with any defaults
	wzFqdn := promptInput("WZ_FQDN", "Enter the Wazuh domain (eg. wazuh.domain.com)", config["WZ_FQDN"])
	wzAPIUsr := promptInput("WZ_API_USR", "Enter the API username (eg. wazuh-wui)", config["WZ_API_USR"])
	wzAPIPasswd := promptInput("WZ_API_PASSWD", "Enter the API passwd", config["WZ_API_PASSWD"])

	fmt.Println("")
	fmt.Println("Retrieving JWT token...")

	// create a POST request with basic auth and skip certificate verification
	url := fmt.Sprintf("https://%s:55000/security/user/authenticate?raw=true", wzFqdn)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		os.Exit(1)
	}
	req.SetBasicAuth(wzAPIUsr, wzAPIPasswd)

	// Create a custom HTTP client that skips certificate verification (-k equivalent)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error during API request: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// read the response body (the token)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		os.Exit(1)
	}
	token := strings.TrimSpace(string(body))

	// Save values to config file
	configContent := fmt.Sprintf(`WZ_FQDN="%s"
WZ_API_USR="%s"
WZ_API_PASSWD="%s"
TOKEN="%s"
`, wzFqdn, wzAPIUsr, wzAPIPasswd, token)
	if err := ioutil.WriteFile(configFilename, []byte(configContent), 0600); err != nil {
		fmt.Printf("Error writing config file: %v\n", err)
		// non-fatal, so we continue
	}

	fmt.Println("")
	fmt.Println("Your JWT auth token is:")
	fmt.Println(token)
	fmt.Println("")
	fmt.Println("=============")
	fmt.Println("    FINIS    ")
	fmt.Println("=============")
}
