/* pkg/eoscli/print.go
 */

package eoscli

import (
	"encoding/json"
	"fmt"
	"os"
)

// PrintBanner prints a formatted ASCII banner with a label.
func printBanner(label string) {
	fmt.Printf("\n───────[ %s ]───────\n", label)
}

// PrintJSON pretty-prints any struct or map as JSON.
func printJSON(data interface{}) {
	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to encode JSON: %v\n", err)
		return
	}
	fmt.Println(string(out))
}
