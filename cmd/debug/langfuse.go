package debug

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/langfuse"
	"github.com/spf13/cobra"
)

var langfuseCmd = &cobra.Command{
	Use:   "langfuse",
	Short: "Debug Langfuse observability deployments",
	Long: `Diagnose common issues with Langfuse deployments including container health,
environment configuration, database state, and HTTP reachability. Example usage:

  eos debug langfuse
  eos debug langfuse --langfuse-container custom-langfuse
  eos debug langfuse --langfuse-url http://langfuse.internal:3000
`,
	RunE: eos_cli.WrapDebug("langfuse", runDebugLangfuse),
}

func init() {
	debugCmd.AddCommand(langfuseCmd)

	langfuseCmd.Flags().String("langfuse-container", "bionicgpt-langfuse", "Langfuse application container name")
	langfuseCmd.Flags().String("database-container", "bionicgpt-langfuse-db", "Langfuse database container name")
	langfuseCmd.Flags().String("langfuse-url", "http://localhost:3000", "Langfuse base URL for HTTP checks")
	langfuseCmd.Flags().String("db-user", "langfuse", "Database user for diagnostics queries")
	langfuseCmd.Flags().String("db-name", "langfuse", "Database name for diagnostics queries")
	langfuseCmd.Flags().Int("log-lines", 200, "Number of log lines to display from Langfuse container")
	langfuseCmd.Flags().Bool("skip-http-check", false, "Skip HTTP reachability test")
}

func runDebugLangfuse(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	langfuseContainer, _ := cmd.Flags().GetString("langfuse-container")
	databaseContainer, _ := cmd.Flags().GetString("database-container")
	langfuseURL, _ := cmd.Flags().GetString("langfuse-url")
	dbUser, _ := cmd.Flags().GetString("db-user")
	dbName, _ := cmd.Flags().GetString("db-name")
	logLines, _ := cmd.Flags().GetInt("log-lines")
	skipHTTP, _ := cmd.Flags().GetBool("skip-http-check")

	cfg := &langfuse.Config{
		LangfuseContainer: langfuseContainer,
		DatabaseContainer: databaseContainer,
		LangfuseURL:       langfuseURL,
		DatabaseUser:      dbUser,
		DatabaseName:      dbName,
		LogTailLines:      logLines,
		SkipHTTPCheck:     skipHTTP,
	}

	return langfuse.RunDiagnostics(rc, cfg)
}
