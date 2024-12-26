package utils

import (
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

// Recursive function to process and print nested YAML structures
func processMap(data map[string]interface{}, indent string) {
	for key, value := range data {
		switch v := value.(type) {
		case map[string]interface{}:
			// If the value is a nested map, call processMap recursively
			fmt.Printf("%s%s:\n", indent, key)
			processMap(v, indent+"  ")
		case []interface{}:
			// If the value is a slice, process each element
			fmt.Printf("%s%s:\n", indent, key)
			for _, item := range v {
				if itemMap, ok := item.(map[string]interface{}); ok {
					processMap(itemMap, indent+"  ")
				} else {
					fmt.Printf("%s  - %v\n", indent, item)
				}
			}
		default:
			// Print scalar values
			fmt.Printf("%s%s: %v\n", indent, key, v)
		}
	}
}

func main() {
	// Specify the path to your YAML file
	yamlFilePath := "config/default.yaml"

	// Read the YAML file
	content, err := os.ReadFile(yamlFilePath)
	if err != nil {
		log.Fatalf("Error reading YAML file: %v\n", err)
	}

	// Parse the YAML content into a generic map
	var data map[string]interface{}
	err = yaml.Unmarshal(content, &data)
	if err != nil {
		log.Fatalf("Error parsing YAML file: %v\n", err)
	}

	// Process and print all values
	fmt.Println("YAML Content:")
	processMap(data, "")
}
