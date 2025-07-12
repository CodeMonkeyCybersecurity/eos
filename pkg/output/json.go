// Package output provides standardized output formatting functions for the Eos CLI.
// This package centralizes all output formatting to ensure consistent presentation
// and proper adherence to CLAUDE.md principles (avoiding direct fmt usage).
package output

import (
	"encoding/json"
	"io"
	"os"
)

// JSONToStdout writes any data structure as formatted JSON to stdout.
// This is the standard way to output JSON data in Eos commands.
//
// Example usage:
//
//	if outputJSON {
//	    return output.JSONToStdout(result)
//	}
func JSONToStdout(data interface{}) error {
	return JSONTo(os.Stdout, data)
}

// JSONTo writes any data structure as formatted JSON to the specified writer.
// This allows for more flexibility when outputting to different destinations.
func JSONTo(w io.Writer, data interface{}) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// JSONToStdoutCompact writes any data structure as compact JSON (no indentation) to stdout.
// Use this when space is a concern or for machine-readable output.
func JSONToStdoutCompact(data interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	return encoder.Encode(data)
}

// JSONToFile writes any data structure as formatted JSON to a file.
// The file is created with 0644 permissions if it doesn't exist.
func JSONToFile(filename string, data interface{}) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return JSONTo(file, data)
}
