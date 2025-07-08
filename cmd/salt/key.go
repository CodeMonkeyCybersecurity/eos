// cmd/salt/key.go
package salt

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt/client"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	keyPattern string
	autoAccept bool
	force      bool
)

// SaltKeyCmd manages Salt minion keys
var SaltKeyCmd = &cobra.Command{
	Use:   "key [command] [key-pattern]",
	Short: "Manage Salt minion authentication keys",
	Long: `Manage Salt minion authentication keys including listing, accepting, rejecting, and deleting keys.

Salt uses a PKI system where minions must have their keys accepted by the master
before they can receive commands. This command provides comprehensive key
management for controlling which minions can communicate with the master.

Commands:
  list                     - List all keys by status
  accept [pattern]         - Accept minion keys
  reject [pattern]         - Reject minion keys  
  delete [pattern]         - Delete minion keys
  status [pattern]         - Show key status for pattern

Key States:
  - Unaccepted: New keys waiting for approval
  - Accepted: Keys approved for communication
  - Rejected: Keys explicitly denied
  - Denied: Keys that failed authentication

Examples:
  eos salt key list                       # List all keys
  eos salt key accept 'web*'              # Accept all web server keys
  eos salt key accept 'new-minion-01'     # Accept specific minion
  eos salt key reject 'suspicious-*'     # Reject suspicious minions
  eos salt key delete 'old-server-*'     # Delete old server keys
  eos salt key status 'db*'              # Check database server key status
  eos salt key accept '*' --auto          # Auto-accept all pending keys
  eos salt key delete 'web01' --force    # Force delete without confirmation
  
Security Considerations:
  - Only accept keys from known, trusted minions
  - Regularly review and clean up old/unused keys
  - Use patterns carefully to avoid unintended actions
  - Consider the security implications of auto-accept
  
Pattern Matching:
  - '*' matches all keys
  - 'web*' matches keys starting with 'web'
  - 'web??' matches 'web' followed by exactly 2 characters
  - Use comma-separated lists for multiple specific keys`,

	Args: cobra.MinimumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		subcommand := args[0]
		pattern := "*"
		if len(args) > 1 {
			pattern = args[1]
		}
		
		logger.Info("Starting Salt key management",
			zap.String("subcommand", subcommand),
			zap.String("pattern", pattern))

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
			return handleKeyList(rc.Ctx, saltClient)
		case "accept":
			return handleKeyAccept(rc.Ctx, saltClient, pattern)
		case "reject":
			return handleKeyReject(rc.Ctx, saltClient, pattern)
		case "delete":
			return handleKeyDelete(rc.Ctx, saltClient, pattern)
		case "status":
			return handleKeyStatus(rc.Ctx, saltClient, pattern)
		default:
			return fmt.Errorf("unknown key subcommand: %s", subcommand)
		}
	}),
}

func init() {
	// Add key-specific flags
	SaltKeyCmd.Flags().StringVar(&keyPattern, "pattern", "*", "Key pattern for operations")
	SaltKeyCmd.Flags().BoolVar(&autoAccept, "auto", false, "Auto-accept without confirmation")
	SaltKeyCmd.Flags().BoolVarP(&force, "force", "f", false, "Force operation without confirmation")
}

// handleKeyList lists all Salt keys by status
func handleKeyList(ctx context.Context, saltClient client.SaltClient) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Listing Salt keys")

	// Since the client interface doesn't have a specific ListKeys method,
	// we'll use a command to get key information
	req := &client.CommandRequest{
		Client:   client.ClientTypeWheel,
		Function: "key.list_all",
	}

	response, err := saltClient.RunCommand(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	if jsonOutput {
		return displayKeyListJSON(response)
	}

	return displayKeyListTable(ctx, response)
}

// handleKeyAccept accepts minion keys matching pattern
func handleKeyAccept(ctx context.Context, saltClient client.SaltClient, pattern string) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Accepting Salt keys", zap.String("pattern", pattern))

	if !autoAccept && !force {
		fmt.Printf("⚠️  About to accept keys matching pattern: %s\n", pattern)
		fmt.Print("Continue? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("❌ Operation cancelled")
			return nil
		}
	}

	err := saltClient.AcceptKey(ctx, pattern)
	if err != nil {
		return fmt.Errorf("failed to accept keys: %w", err)
	}

	fmt.Printf("✅ Accepted keys matching pattern: %s\n", pattern)
	logger.Info("Keys accepted successfully", zap.String("pattern", pattern))

	return nil
}

// handleKeyReject rejects minion keys matching pattern
func handleKeyReject(ctx context.Context, saltClient client.SaltClient, pattern string) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Rejecting Salt keys", zap.String("pattern", pattern))

	if !force {
		fmt.Printf("⚠️  About to reject keys matching pattern: %s\n", pattern)
		fmt.Print("Continue? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("❌ Operation cancelled")
			return nil
		}
	}

	err := saltClient.RejectKey(ctx, pattern)
	if err != nil {
		return fmt.Errorf("failed to reject keys: %w", err)
	}

	fmt.Printf("❌ Rejected keys matching pattern: %s\n", pattern)
	logger.Info("Keys rejected successfully", zap.String("pattern", pattern))

	return nil
}

// handleKeyDelete deletes minion keys matching pattern
func handleKeyDelete(ctx context.Context, saltClient client.SaltClient, pattern string) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Deleting Salt keys", zap.String("pattern", pattern))

	if !force {
		fmt.Printf("⚠️  About to DELETE keys matching pattern: %s\n", pattern)
		fmt.Printf("🚨 This action cannot be undone!\n")
		fmt.Print("Continue? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("❌ Operation cancelled")
			return nil
		}
	}

	err := saltClient.DeleteKey(ctx, pattern)
	if err != nil {
		return fmt.Errorf("failed to delete keys: %w", err)
	}

	fmt.Printf("🗑️  Deleted keys matching pattern: %s\n", pattern)
	logger.Info("Keys deleted successfully", zap.String("pattern", pattern))

	return nil
}

// handleKeyStatus shows key status for pattern
func handleKeyStatus(ctx context.Context, saltClient client.SaltClient, pattern string) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Getting key status", zap.String("pattern", pattern))

	// Get key status using wheel function
	req := &client.CommandRequest{
		Client:   client.ClientTypeWheel,
		Function: "key.list_all",
	}

	response, err := saltClient.RunCommand(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get key status: %w", err)
	}

	if jsonOutput {
		return displayKeyStatusJSON(response, pattern)
	}

	return displayKeyStatusTable(ctx, response, pattern)
}

// Display functions

func displayKeyListJSON(response *client.CommandResponse) error {
	jsonData, err := json.MarshalIndent(response.Return, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func displayKeyListTable(ctx context.Context, response *client.CommandResponse) error {
	if len(response.Return) == 0 {
		fmt.Println("📭 No key data available")
		return nil
	}

	fmt.Printf("\n🔑 Salt Keys Status\n")
	fmt.Printf("==================\n")

	// Parse key data from response
	keyData := parseKeyData(response.Return)

	// Display keys by status
	if len(keyData.Accepted) > 0 {
		fmt.Printf("\n✅ Accepted Keys (%d):\n", len(keyData.Accepted))
		for _, key := range keyData.Accepted {
			fmt.Printf("   • %s\n", key)
		}
	}

	if len(keyData.Unaccepted) > 0 {
		fmt.Printf("\n⏳ Unaccepted Keys (%d):\n", len(keyData.Unaccepted))
		for _, key := range keyData.Unaccepted {
			fmt.Printf("   • %s\n", key)
		}
	}

	if len(keyData.Rejected) > 0 {
		fmt.Printf("\n❌ Rejected Keys (%d):\n", len(keyData.Rejected))
		for _, key := range keyData.Rejected {
			fmt.Printf("   • %s\n", key)
		}
	}

	if len(keyData.Denied) > 0 {
		fmt.Printf("\n🚫 Denied Keys (%d):\n", len(keyData.Denied))
		for _, key := range keyData.Denied {
			fmt.Printf("   • %s\n", key)
		}
	}

	// Summary
	total := len(keyData.Accepted) + len(keyData.Unaccepted) + len(keyData.Rejected) + len(keyData.Denied)
	fmt.Printf("\n📊 Summary: %d total keys\n", total)

	if len(keyData.Unaccepted) > 0 {
		fmt.Printf("💡 Use 'eos salt key accept <pattern>' to accept pending keys\n")
	}

	return nil
}

func displayKeyStatusJSON(response *client.CommandResponse, pattern string) error {
	keyData := parseKeyData(response.Return)
	
	// Filter by pattern if specified
	filtered := filterKeysByPattern(keyData, pattern)
	
	jsonData, err := json.MarshalIndent(filtered, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func displayKeyStatusTable(ctx context.Context, response *client.CommandResponse, pattern string) error {
	keyData := parseKeyData(response.Return)
	filtered := filterKeysByPattern(keyData, pattern)

	fmt.Printf("\n🔑 Key Status for pattern: %s\n", pattern)
	fmt.Printf("================================\n")

	total := 0
	if len(filtered.Accepted) > 0 {
		fmt.Printf("✅ Accepted: %d\n", len(filtered.Accepted))
		total += len(filtered.Accepted)
	}
	if len(filtered.Unaccepted) > 0 {
		fmt.Printf("⏳ Unaccepted: %d\n", len(filtered.Unaccepted))
		total += len(filtered.Unaccepted)
	}
	if len(filtered.Rejected) > 0 {
		fmt.Printf("❌ Rejected: %d\n", len(filtered.Rejected))
		total += len(filtered.Rejected)
	}
	if len(filtered.Denied) > 0 {
		fmt.Printf("🚫 Denied: %d\n", len(filtered.Denied))
		total += len(filtered.Denied)
	}

	if total == 0 {
		fmt.Printf("📭 No keys found matching pattern: %s\n", pattern)
	} else {
		fmt.Printf("\n📊 Total matching keys: %d\n", total)
	}

	return nil
}

// KeyData represents the structure of Salt key data
type KeyData struct {
	Accepted   []string `json:"accepted"`
	Unaccepted []string `json:"unaccepted"`
	Rejected   []string `json:"rejected"`
	Denied     []string `json:"denied"`
}

// parseKeyData extracts key information from Salt response
func parseKeyData(returnData []map[string]interface{}) *KeyData {
	keyData := &KeyData{
		Accepted:   []string{},
		Unaccepted: []string{},
		Rejected:   []string{},
		Denied:     []string{},
	}

	if len(returnData) == 0 {
		return keyData
	}

	// Extract key data from the first return item
	data := returnData[0]

	if accepted, ok := data["minions"].([]interface{}); ok {
		for _, key := range accepted {
			if keyStr, ok := key.(string); ok {
				keyData.Accepted = append(keyData.Accepted, keyStr)
			}
		}
	}

	if unaccepted, ok := data["minions_pre"].([]interface{}); ok {
		for _, key := range unaccepted {
			if keyStr, ok := key.(string); ok {
				keyData.Unaccepted = append(keyData.Unaccepted, keyStr)
			}
		}
	}

	if rejected, ok := data["minions_rejected"].([]interface{}); ok {
		for _, key := range rejected {
			if keyStr, ok := key.(string); ok {
				keyData.Rejected = append(keyData.Rejected, keyStr)
			}
		}
	}

	if denied, ok := data["minions_denied"].([]interface{}); ok {
		for _, key := range denied {
			if keyStr, ok := key.(string); ok {
				keyData.Denied = append(keyData.Denied, keyStr)
			}
		}
	}

	return keyData
}

// filterKeysByPattern filters keys based on a pattern
func filterKeysByPattern(keyData *KeyData, pattern string) *KeyData {
	if pattern == "*" || pattern == "" {
		return keyData
	}

	filtered := &KeyData{
		Accepted:   []string{},
		Unaccepted: []string{},
		Rejected:   []string{},
		Denied:     []string{},
	}

	// Simple pattern matching (could be enhanced with proper glob matching)
	for _, key := range keyData.Accepted {
		if matchesPattern(key, pattern) {
			filtered.Accepted = append(filtered.Accepted, key)
		}
	}

	for _, key := range keyData.Unaccepted {
		if matchesPattern(key, pattern) {
			filtered.Unaccepted = append(filtered.Unaccepted, key)
		}
	}

	for _, key := range keyData.Rejected {
		if matchesPattern(key, pattern) {
			filtered.Rejected = append(filtered.Rejected, key)
		}
	}

	for _, key := range keyData.Denied {
		if matchesPattern(key, pattern) {
			filtered.Denied = append(filtered.Denied, key)
		}
	}

	return filtered
}

// matchesPattern performs simple pattern matching
func matchesPattern(key, pattern string) bool {
	// For now, implement simple prefix matching
	// This could be enhanced with proper glob pattern matching
	if pattern == "*" {
		return true
	}
	
	// Handle wildcard at end of pattern
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(key) >= len(prefix) && key[:len(prefix)] == prefix
	}
	
	// Exact match
	return key == pattern
}