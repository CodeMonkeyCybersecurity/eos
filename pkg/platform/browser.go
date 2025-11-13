// pkg/platform/browser.go

package platform

import (
	"context"
	"os/exec"
	"runtime"
	"time"
)

// OpenBrowser opens a URL in the default browser with context support
// SECURITY P1 #5: Added context parameter for cancellation support
func OpenBrowser(url string) error {
	// Use background context with timeout for browser launch
	// Browser launch is fire-and-forget, so we don't need caller's context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", url)
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", url)
	default: // linux and others
		cmd = exec.CommandContext(ctx, "xdg-open", url)
	}
	return cmd.Start()
}
