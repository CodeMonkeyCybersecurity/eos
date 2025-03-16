// cmd/refresh/refresh.go
package refresh

import (
    "github.com/spf13/cobra"
)

// RefreshCmd represents the refresh parent command.
var RefreshCmd = &cobra.Command{
    Use:   "refresh",
    Short: "Refresh commands",
    Long:  "Commands to refresh or reload components.",
}
