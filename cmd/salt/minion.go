// cmd/salt/minion.go
package salt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt/client"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	minionStatus string
	minionGrain  string
	showGrains   bool
	showPillar   bool
	refreshData  bool
)

// SaltMinionCmd manages Salt minions
var SaltMinionCmd = &cobra.Command{
	Use:   "minion [command] [target] [args...]",
	Short: "Manage Salt minions - list, inspect, and control minion systems",
	Long: `Manage Salt minions including listing, inspecting grains and pillar data,
and refreshing minion information.

Minions are the systems managed by Salt that execute commands and maintain
desired state. This command provides comprehensive minion management
capabilities for monitoring and controlling your infrastructure.

Commands:
  list [pattern]           - List minions matching pattern
  info [target]            - Get detailed minion information  
  grains [target] [grain]  - Show grains data for minions
  pillar [target] [key]    - Show pillar data for minions
  refresh [target]         - Refresh minion data cache
  status                   - Show minion connectivity status

Examples:
  eos salt minion list                    # List all minions
  eos salt minion list 'web*'             # List web server minions
  eos salt minion list --status up        # List only responsive minions
  eos salt minion info 'web01'            # Get detailed info for specific minion
  eos salt minion grains '*' os           # Show OS grain for all minions
  eos salt minion grains 'db*'            # Show all grains for database servers
  eos salt minion pillar 'app*' users     # Show users pillar for app servers
  eos salt minion refresh '*'             # Refresh all minion data
  eos salt minion status                  # Show connectivity status
  
Targeting:
  Use Salt targeting expressions to specify minions:
  - '*' - All minions
  - 'web*' - All minions starting with 'web'
  - 'web01,web02' - Specific minions (comma-separated)
  - Use --target-type for advanced targeting (grain, pillar, etc.)
  
Data Types:
  - Grains: Static system information (OS, hardware, network)
  - Pillar: Configuration data specific to minions
  - Status: Real-time connectivity and responsiveness`,

	Args: cobra.MinimumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		subcommand := args[0]
		
		logger.Info("Starting Salt minion management",
			zap.String("subcommand", subcommand))

		// Get Salt client configuration
		config, err := getSaltConfig()
		if err != nil {
			return fmt.Errorf("Salt configuration error: %w", err)
		}

		// Create Salt client
		clientConfig := &client.ClientConfig{
			BaseURL:       config.URL,
			Username:      config.Username,
			Password:      config.Password,
			Eauth:         config.Eauth,
			Timeout:       time.Duration(config.Timeout) * time.Second,
			MaxRetries:    config.Retries,
			RetryDelay:    2 * time.Second,
		}

		saltClient, err := client.NewHTTPSaltClient(rc, clientConfig)
		if err != nil {
			return fmt.Errorf("failed to create Salt client: %w", err)
		}

		// Authenticate with Salt API
		logger.Info("Authenticating with Salt API")
		_, err = saltClient.Login(rc.Ctx, nil)
		if err != nil {
			return fmt.Errorf("Salt API authentication failed: %w", err)
		}
		defer func() {
			if err := saltClient.Logout(rc.Ctx); err != nil {
				logger.Warn("Failed to logout from Salt API", zap.Error(err))
			}
		}()

		// Route to appropriate subcommand
		switch subcommand {
		case "list":
			target := "*"
			if len(args) > 1 {
				target = args[1]
			}
			return handleMinionList(rc.Ctx, saltClient, target)
		case "info":
			if len(args) < 2 {
				return fmt.Errorf("minion target required for info command")
			}
			return handleMinionInfo(rc.Ctx, saltClient, args[1])
		case "grains":
			if len(args) < 2 {
				return fmt.Errorf("minion target required for grains command")
			}
			target := args[1]
			grain := ""
			if len(args) > 2 {
				grain = args[2]
			}
			return handleMinionGrains(rc.Ctx, saltClient, target, grain)
		case "pillar":
			if len(args) < 2 {
				return fmt.Errorf("minion target required for pillar command")
			}
			target := args[1]
			key := ""
			if len(args) > 2 {
				key = args[2]
			}
			return handleMinionPillar(rc.Ctx, saltClient, target, key)
		case "refresh":
			target := "*"
			if len(args) > 1 {
				target = args[1]
			}
			return handleMinionRefresh(rc.Ctx, saltClient, target)
		case "status":
			return handleMinionStatus(rc.Ctx, saltClient)
		default:
			return fmt.Errorf("unknown minion subcommand: %s", subcommand)
		}
	}),
}

func init() {
	// Add minion-specific flags
	SaltMinionCmd.Flags().StringVar(&minionStatus, "status", "", "Filter minions by status (up, down)")
	SaltMinionCmd.Flags().StringVar(&minionGrain, "grain", "", "Filter minions by grain value")
	SaltMinionCmd.Flags().BoolVar(&showGrains, "show-grains", false, "Include grains in output")
	SaltMinionCmd.Flags().BoolVar(&showPillar, "show-pillar", false, "Include pillar in output")
	SaltMinionCmd.Flags().BoolVar(&refreshData, "refresh", false, "Refresh minion data before showing")
}

// handleMinionList lists minions with optional filtering
func handleMinionList(ctx context.Context, saltClient client.SaltClient, target string) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Listing Salt minions",
		zap.String("target", target),
		zap.String("status_filter", minionStatus))

	opts := &client.MinionListOptions{}
	if minionStatus != "" {
		opts.Status = minionStatus
	}

	minions, err := saltClient.ListMinions(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to list minions: %w", err)
	}

	if jsonOutput {
		return displayMinionListJSON(minions)
	}

	return displayMinionListTable(ctx, minions, target)
}

// handleMinionInfo shows detailed information for a specific minion
func handleMinionInfo(ctx context.Context, saltClient client.SaltClient, target string) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Getting minion info", zap.String("target", target))

	// Refresh data if requested
	if refreshData {
		logger.Info("Refreshing minion data")
		err := saltClient.RefreshPillar(ctx, target)
		if err != nil {
			logger.Warn("Failed to refresh pillar data", zap.Error(err))
		}
	}

	info, err := saltClient.GetMinionInfo(ctx, target)
	if err != nil {
		return fmt.Errorf("failed to get minion info: %w", err)
	}

	if jsonOutput {
		return displayMinionInfoJSON(info)
	}

	return displayMinionInfoTable(ctx, info)
}

// handleMinionGrains shows grains data for minions
func handleMinionGrains(ctx context.Context, saltClient client.SaltClient, target, grain string) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Getting minion grains",
		zap.String("target", target),
		zap.String("grain", grain))

	grains, err := saltClient.GetGrains(ctx, target)
	if err != nil {
		return fmt.Errorf("failed to get grains: %w", err)
	}

	if jsonOutput {
		return displayGrainsJSON(grains, grain)
	}

	return displayGrainsTable(ctx, grains, grain)
}

// handleMinionPillar shows pillar data for minions
func handleMinionPillar(ctx context.Context, saltClient client.SaltClient, target, key string) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Getting minion pillar",
		zap.String("target", target),
		zap.String("key", key))

	pillar, err := saltClient.GetPillar(ctx, target, key)
	if err != nil {
		return fmt.Errorf("failed to get pillar: %w", err)
	}

	if jsonOutput {
		return displayPillarJSON(pillar, key)
	}

	return displayPillarTable(ctx, pillar, key)
}

// handleMinionRefresh refreshes minion data cache
func handleMinionRefresh(ctx context.Context, saltClient client.SaltClient, target string) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Refreshing minion data", zap.String("target", target))

	err := saltClient.RefreshPillar(ctx, target)
	if err != nil {
		return fmt.Errorf("failed to refresh minion data: %w", err)
	}

	fmt.Printf("✅ Refreshed data for minions matching: %s\n", target)
	return nil
}

// handleMinionStatus shows minion connectivity status
func handleMinionStatus(ctx context.Context, saltClient client.SaltClient) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Getting minion status")

	minions, err := saltClient.ListMinions(ctx, &client.MinionListOptions{})
	if err != nil {
		return fmt.Errorf("failed to get minion status: %w", err)
	}

	if jsonOutput {
		return displayMinionStatusJSON(minions)
	}

	return displayMinionStatusTable(ctx, minions)
}

// Display functions

func displayMinionListJSON(minions *client.MinionList) error {
	jsonData, err := json.MarshalIndent(minions, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func displayMinionListTable(ctx context.Context, minions *client.MinionList, target string) error {
	if len(minions.Minions) == 0 {
		fmt.Printf("📭 No minions found matching: %s\n", target)
		return nil
	}

	fmt.Printf("\n🖥️  Salt Minions (%d found)\n", len(minions.Minions))
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("==========================\n")
	fmt.Printf("%-20s %-10s %-15s %-15s %-s\n", "Minion ID", "Status", "OS", "Version", "IP Address")
	fmt.Printf("%-20s %-10s %-15s %-15s %-s\n", "---------", "------", "--", "-------", "----------")

	for _, minion := range minions.Minions {
		status := minion.Status
		statusIcon := "❓"
		switch status {
		case "up":
			statusIcon = "✅"
		case "down":
			statusIcon = "❌"
		}

		os := minion.OS
		if os == "" {
			os = "unknown"
		}

		version := minion.OSVersion
		if version == "" {
			version = "unknown"
		}

		ip := minion.IPAddress
		if ip == "" {
			ip = "unknown"
		}

		fmt.Printf("%-20s %s %-8s %-15s %-15s %-s\n", 
			minion.ID, statusIcon, status, os, version, ip)
	}

	// Summary
	upCount := 0
	downCount := 0
	for _, minion := range minions.Minions {
		if minion.Status == "up" {
			upCount++
		} else {
			downCount++
		}
	}

	fmt.Printf("\n📊 Summary: %d total, %d up, %d down\n", len(minions.Minions), upCount, downCount)
	return nil
}

func displayMinionInfoJSON(info *client.MinionInfo) error {
	jsonData, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func displayMinionInfoTable(ctx context.Context, info *client.MinionInfo) error {
	fmt.Printf("\n🖥️  Minion Information: %s\n", info.ID)
	fmt.Printf("================================\n")
	fmt.Printf("Status: %s\n", info.Status)
	fmt.Printf("Last Seen: %s\n", info.LastSeen.Format("2006-01-02 15:04:05"))
	fmt.Printf("OS: %s\n", info.OS)
	fmt.Printf("OS Version: %s\n", info.OSVersion)
	fmt.Printf("IP Address: %s\n", info.IPAddress)
	fmt.Printf("Salt Version: %s\n", info.Version)

	if showGrains && info.Grains != nil {
		fmt.Printf("\n📊 Grains:\n")
		displayDataMap(info.Grains, "  ")
	}

	if showPillar && info.Pillar != nil {
		fmt.Printf("\n🗂️  Pillar:\n")
		displayDataMap(info.Pillar, "  ")
	}

	return nil
}

func displayGrainsJSON(grains *client.GrainsData, grain string) error {
	var data interface{}
	if grain != "" {
		data = grains.Grains[grain]
	} else {
		data = grains
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func displayGrainsTable(ctx context.Context, grains *client.GrainsData, grain string) error {
	fmt.Printf("\n📊 Grains for %s\n", grains.MinionID)
	fmt.Printf("=================\n")

	if grain != "" {
		// Show specific grain
		if value, exists := grains.Grains[grain]; exists {
			fmt.Printf("%s: %v\n", grain, value)
		} else {
			fmt.Printf("Grain '%s' not found\n", grain)
		}
	} else {
		// Show all grains
		displayDataMap(grains.Grains, "")
	}

	return nil
}

func displayPillarJSON(pillar *client.PillarData, key string) error {
	var data interface{}
	if key != "" {
		data = pillar.Data[key]
	} else {
		data = pillar
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func displayPillarTable(ctx context.Context, pillar *client.PillarData, key string) error {
	fmt.Printf("\n🗂️  Pillar for %s\n", pillar.MinionID)
	fmt.Printf("=================\n")

	if key != "" {
		// Show specific pillar key
		if value, exists := pillar.Data[key]; exists {
			fmt.Printf("%s: %v\n", key, value)
		} else {
			fmt.Printf("Pillar key '%s' not found\n", key)
		}
	} else {
		// Show all pillar data
		displayDataMap(pillar.Data, "")
	}

	return nil
}

func displayMinionStatusJSON(minions *client.MinionList) error {
	status := map[string]interface{}{
		"total":   len(minions.Minions),
		"up":      0,
		"down":    0,
		"minions": minions.Minions,
	}

	for _, minion := range minions.Minions {
		if minion.Status == "up" {
			status["up"] = status["up"].(int) + 1
		} else {
			status["down"] = status["down"].(int) + 1
		}
	}

	jsonData, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func displayMinionStatusTable(ctx context.Context, minions *client.MinionList) error {
	upCount := 0
	downCount := 0
	upMinions := []string{}
	downMinions := []string{}

	for _, minion := range minions.Minions {
		if minion.Status == "up" {
			upCount++
			upMinions = append(upMinions, minion.ID)
		} else {
			downCount++
			downMinions = append(downMinions, minion.ID)
		}
	}

	fmt.Printf("\n📊 Minion Status Summary\n")
	fmt.Printf("========================\n")
	fmt.Printf("Total Minions: %d\n", len(minions.Minions))
	fmt.Printf("Up: %d\n", upCount)
	fmt.Printf("Down: %d\n", downCount)

	if len(upMinions) > 0 {
		fmt.Printf("\n✅ Up Minions (%d):\n", len(upMinions))
		for _, minion := range upMinions {
			fmt.Printf("   • %s\n", minion)
		}
	}

	if len(downMinions) > 0 {
		fmt.Printf("\n❌ Down Minions (%d):\n", len(downMinions))
		for _, minion := range downMinions {
			fmt.Printf("   • %s\n", minion)
		}
	}

	return nil
}

// displayDataMap recursively displays nested map data
func displayDataMap(data map[string]interface{}, indent string) {
	for key, value := range data {
		switch v := value.(type) {
		case map[string]interface{}:
			fmt.Printf("%s%s:\n", indent, key)
			displayDataMap(v, indent+"  ")
		case []interface{}:
			fmt.Printf("%s%s: [", indent, key)
			for i, item := range v {
				if i > 0 {
					fmt.Print(", ")
				}
				fmt.Printf("%v", item)
			}
			fmt.Println("]")
		case string:
			// Handle multi-line strings
			if strings.Contains(v, "\n") {
				fmt.Printf("%s%s: |\n", indent, key)
				lines := strings.Split(v, "\n")
				for _, line := range lines {
					fmt.Printf("%s  %s\n", indent, line)
				}
			} else {
				fmt.Printf("%s%s: %s\n", indent, key, v)
			}
		default:
			fmt.Printf("%s%s: %v\n", indent, key, v)
		}
	}
}