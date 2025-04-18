// cmd/treecat.go

package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/types"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
)

var TreecatCmd = &cobra.Command{
	Use:   "treecat [path]",
	Short: "Recursively show directory structure and preview file contents",
	Args:  cobra.ExactArgs(1),
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()
		root := args[0]

		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				log.Warn("Skipping path due to error", zap.String("path", path), zap.Error(err))
				return nil
			}

			relPath, _ := filepath.Rel(root, path)
			depth := strings.Count(relPath, string(os.PathSeparator))
			indent := strings.Repeat("  ", depth)

			fmt.Printf("%s- %s\n", indent, d.Name())

			if d.Type().IsRegular() {
				preview, err := previewFile(path)
				if err != nil {
					log.Warn("Could not preview file", zap.String("file", path), zap.Error(err))
					return nil
				}

				if preview != "" {
					fmt.Printf("%s  \033[90m%s\033[0m\n", indent, strings.ReplaceAll(preview, "\n", "\n"+indent+"  "))
				}
			}
			return nil
		})

		if err != nil {
			log.Error("Failed to walk directory", zap.Error(err))
			os.Exit(1)
		}
		return nil
	}),
}

func previewFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, types.MaxPreviewSize)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}

	content := string(buf[:n])
	if !utf8.ValidString(content) {
		return "(binary or non-UTF8 file omitted)", nil
	}

	// Rewind and read line-by-line for nicer preview
	_, _ = f.Seek(0, 0)
	scanner := bufio.NewScanner(f)
	var lines []string
	for i := 0; scanner.Scan() && i < types.MaxPreviewLines; i++ {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return strings.Join(lines, "\n"), nil
}

func init() {
	// Attach to root command in your main.go or cmd/root.go
	// Example: rootCmd.AddCommand(treecatCmd)
}

// To hook it up, make sure you do:
// In cmd/root.go or main.go:
// import _ "github.com/CodeMonkeyCybersecurity/eos/cmd/treecat"
// And call treecat.init() or AddCommand(treecatCmd) appropriately
