// pkg/utils/inspect.go

package utils

import (
	"fmt"
	"os"
	"strings"
)


func InspectCertificates() {
	certsDir := "certs"
	fmt.Printf("\n--- Inspecting Certificates in '%s' ---\n", certsDir)
	files, err := os.ReadDir(certsDir)
	if err != nil {
		fmt.Printf("Error reading certificates directory: %v\n", err)
		return
	}
	if len(files) == 0 {
		fmt.Println("No certificates found.")
		return
	}
	for _, file := range files {
		fmt.Printf(" - %s\n", file.Name())
	}
}

func InspectDockerCompose() {
	configFile := "docker-compose.yml"
	fmt.Printf("\n--- Inspecting docker-compose file: %s ---\n", configFile)
	data, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", configFile, err)
		return
	}
	fmt.Println(string(data))
}

func InspectEosConfig() {
	confDir := "conf.d"
	fmt.Printf("\n--- Inspecting Eos backend web apps configuration in '%s' ---\n", confDir)
	files, err := os.ReadDir(confDir)
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", confDir, err)
		return
	}
	found := false
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".conf") {
			fmt.Printf(" - %s\n", file.Name())
			found = true
		}
	}
	if !found {
		fmt.Println("No Eos configuration files found.")
	}
}

func InspectNginxDefaults() {
	configFile := "http.conf"
	fmt.Printf("\n--- Inspecting Nginx defaults in %s ---\n", configFile)
	data, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", configFile, err)
		return
	}
	fmt.Println(string(data))
}
