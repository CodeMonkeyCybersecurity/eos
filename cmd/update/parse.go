package update

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
)

var (
	inputFile string
	jsonMode  bool
)

var ParseCmd = &cobra.Command{
	Use:   "parse",
	Short: "Split a ChatGPT-style conversations.json into individual files",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		if !jsonMode {
			return fmt.Errorf("only --json mode is currently supported")
		}

		// Open and decode input file
		file, err := os.Open(inputFile)
		if err != nil {
			return fmt.Errorf("failed to open input file: %w", err)
		}
		defer shared.SafeClose(rc.Ctx, file)

		var conversations []map[string]interface{}
		if err := json.NewDecoder(file).Decode(&conversations); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}

		// Create output dir if needed
		outDir := "parsed_conversations"
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		// Write each top-level conversation as a separate file
		for i, conv := range conversations {
			outPath := filepath.Join(outDir, fmt.Sprintf("conv_%03d.json", i))
			outFile, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}
			defer shared.SafeClose(rc.Ctx, outFile) // Safe close each file

			enc := json.NewEncoder(outFile)
			enc.SetIndent("", "  ")
			if err := enc.Encode(conv); err != nil {
				return fmt.Errorf("failed to write JSON: %w", err)
			}
		}

		fmt.Printf(" Parsed %d conversations into ./%s/\n", len(conversations), outDir)
		return nil
	}),
}

func init() {
	ParseCmd.Flags().StringVar(&inputFile, "filename", "", "Path to conversations.json")
	ParseCmd.Flags().BoolVar(&jsonMode, "json", false, "Enable JSON parse mode")
	_ = ParseCmd.MarkFlagRequired("filename")
}
