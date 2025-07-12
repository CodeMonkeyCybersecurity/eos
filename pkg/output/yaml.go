// Package output provides YAML formatting utilities
package output

import (
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// YAMLToStdout writes any data structure as formatted YAML to stdout.
// This is the standard way to output YAML data in Eos commands.
//
// Example usage:
//
//	if outputYAML {
//	    return output.YAMLToStdout(result)
//	}
func YAMLToStdout(data interface{}) error {
	return YAMLTo(os.Stdout, data)
}

// YAMLTo writes any data structure as formatted YAML to the specified writer.
// The encoder is properly closed after writing.
func YAMLTo(w io.Writer, data interface{}) error {
	encoder := yaml.NewEncoder(w)
	defer encoder.Close()

	// Set indent to 2 spaces for readability
	encoder.SetIndent(2)

	return encoder.Encode(data)
}

// YAMLToFile writes any data structure as formatted YAML to a file.
// The file is created with 0644 permissions if it doesn't exist.
func YAMLToFile(filename string, data interface{}) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return YAMLTo(file, data)
}

// YAMLToString converts any data structure to a YAML string.
// Useful for logging or embedding YAML in other outputs.
func YAMLToString(data interface{}) (string, error) {
	output, err := yaml.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(output), nil
}
