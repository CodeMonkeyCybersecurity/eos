package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO: This is a refactored version of export_display.go following Eos standards:
// - All fmt.Printf/Println replaced with structured logging or stderr output
// - User-facing output uses stderr to preserve stdout
// - Follows Assess → Intervene → Evaluate pattern
// - Enhanced error handling and context

// ExportToJSONRefactored exports VaultInitInfo to JSON format following Eos standards
func ExportToJSONRefactored(rc *eos_io.RuntimeContext, info *VaultInitInfo, options *ReadInitOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Prepare JSON export
	logger.Info("Assessing JSON export requirements",
		zap.String("output_path", options.OutputPath),
		zap.Bool("redacted", options.RedactSensitive))
	
	// Validate output directory
	if options.OutputPath != "" {
		dir := filepath.Dir(options.OutputPath)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("output directory does not exist: %s", dir)
		}
	}
	
	// INTERVENE - Marshal data to JSON
	logger.Info("Marshalling vault data to JSON")
	
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		logger.Error("Failed to marshal JSON", zap.Error(err))
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	
	// Output JSON data
	if options.OutputPath == "" {
		// Output to stdout for piping/redirection
		if _, err := fmt.Print(string(data)); err != nil {
			return fmt.Errorf("failed to output JSON: %w", err)
		}
		logger.Info("JSON data output to stdout")
	} else {
		// Write to file
		if err := os.WriteFile(options.OutputPath, data, 0600); err != nil {
			logger.Error("Failed to write JSON file", zap.Error(err))
			return fmt.Errorf("failed to write JSON file: %w", err)
		}
		
		// Log success and display to user
		logger.Info("JSON data exported to file",
			zap.String("path", options.OutputPath))
			
		// User notification via stderr
		if _, err := fmt.Fprintf(os.Stderr, "🔐 Vault init data exported securely to: %s\n", options.OutputPath); err != nil {
			return fmt.Errorf("failed to display export message: %w", err)
		}
	}
	
	// EVALUATE - Verify export success
	logger.Info("Evaluating JSON export results")
	
	if options.OutputPath != "" {
		// Verify file was created and has content
		if stat, err := os.Stat(options.OutputPath); err != nil {
			return fmt.Errorf("failed to verify exported file: %w", err)
		} else if stat.Size() == 0 {
			return fmt.Errorf("exported file is empty")
		}
	}
	
	logger.Info("JSON export completed successfully")
	return nil
}

// DisplayVaultStatusRefactored displays comprehensive vault status following Eos standards
func DisplayVaultStatusRefactored(rc *eos_io.RuntimeContext, info *VaultInitInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Displaying vault status overview")
	
	// ASSESS - Prepare status display
	logger.Info("Assessing vault status information")
	
	// INTERVENE - Format and display status
	if err := displayVaultStatusHeader(rc); err != nil {
		return fmt.Errorf("failed to display status header: %w", err)
	}
	
	if err := displayFileInfo(rc, info); err != nil {
		return fmt.Errorf("failed to display file info: %w", err)
	}
	
	if err := displayVaultInfo(rc, info); err != nil {
		return fmt.Errorf("failed to display vault info: %w", err)
	}
	
	if err := displayTokenInfo(rc, info); err != nil {
		return fmt.Errorf("failed to display token info: %w", err)
	}
	
	if err := displayMountInfo(rc, info); err != nil {
		return fmt.Errorf("failed to display mount info: %w", err)
	}
	
	if err := displayUnsealInfo(rc, info); err != nil {
		return fmt.Errorf("failed to display unseal info: %w", err)
	}
	
	// EVALUATE - Verify display completed
	logger.Info("Vault status display completed successfully")
	return nil
}

// displayVaultStatusHeader displays the status overview header
func displayVaultStatusHeader(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("terminal prompt: Vault Status Overview")
	
	header := `
🏦 Vault Status Overview
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`
	
	if _, err := fmt.Fprint(os.Stderr, header); err != nil {
		return fmt.Errorf("failed to display header: %w", err)
	}
	
	return nil
}

// displayFileInfo displays vault init file information
func displayFileInfo(rc *eos_io.RuntimeContext, info *VaultInitInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Displaying vault file information")
	
	var fileInfo strings.Builder
	fileInfo.WriteString(fmt.Sprintf("\n📁 Init File: %s\n", info.FileInfo.Path))
	fileInfo.WriteString(fmt.Sprintf("   Exists: %v\n", info.FileInfo.Exists))
	fileInfo.WriteString(fmt.Sprintf("   Readable: %v\n", info.FileInfo.Readable))
	
	if info.FileInfo.Exists {
		fileInfo.WriteString(fmt.Sprintf("   Size: %d bytes\n", info.FileInfo.Size))
		fileInfo.WriteString(fmt.Sprintf("   Modified: %s\n", info.FileInfo.ModTime.Format("2006-01-02 15:04:05")))
	}
	
	if _, err := fmt.Fprint(os.Stderr, fileInfo.String()); err != nil {
		return fmt.Errorf("failed to display file info: %w", err)
	}
	
	return nil
}

// displayVaultInfo displays vault server information
func displayVaultInfo(rc *eos_io.RuntimeContext, info *VaultInitInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Displaying vault server information")
	
	var vaultInfo strings.Builder
	vaultInfo.WriteString("\n🏦 Vault Status\n")
	vaultInfo.WriteString(fmt.Sprintf("   Address: %s\n", info.VaultStatus.Address))
	vaultInfo.WriteString(fmt.Sprintf("   Running: %v\n", info.VaultStatus.Running))
	vaultInfo.WriteString(fmt.Sprintf("   Reachable: %v\n", info.VaultStatus.Reachable))
	vaultInfo.WriteString(fmt.Sprintf("   Initialized: %v\n", info.VaultStatus.Initialized))
	vaultInfo.WriteString(fmt.Sprintf("   Sealed: %v\n", info.VaultStatus.Sealed))
	
	if _, err := fmt.Fprint(os.Stderr, vaultInfo.String()); err != nil {
		return fmt.Errorf("failed to display vault info: %w", err)
	}
	
	return nil
}

// displayTokenInfo displays vault token information
func displayTokenInfo(rc *eos_io.RuntimeContext, info *VaultInitInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Displaying vault token information")
	
	var tokenInfo strings.Builder
	tokenInfo.WriteString("\n🔑 Token Information\n")
	
	if info.InitResponse != nil && info.InitResponse.RootToken != "" {
		tokenInfo.WriteString(fmt.Sprintf("   Root Token: %s\n", maskSensitiveData(info.InitResponse.RootToken)))
		tokenInfo.WriteString("   Status: Available\n")
	} else {
		tokenInfo.WriteString("   Root Token: Not available\n")
	}
	
	if _, err := fmt.Fprint(os.Stderr, tokenInfo.String()); err != nil {
		return fmt.Errorf("failed to display token info: %w", err)
	}
	
	return nil
}

// displayMountInfo displays vault mount information
func displayMountInfo(rc *eos_io.RuntimeContext, info *VaultInitInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Displaying vault mount information")
	
	var mountInfo strings.Builder
	mountInfo.WriteString("\n💾 Mount Points\n")
	
	// Note: Mount information would come from vault status if available
	// This is a placeholder since the actual mount info structure needs to be defined
	mountInfo.WriteString("   Secret engines: Available via vault status\n")
	mountInfo.WriteString("   Auth methods: Available via vault status\n")
	
	if _, err := fmt.Fprint(os.Stderr, mountInfo.String()); err != nil {
		return fmt.Errorf("failed to display mount info: %w", err)
	}
	
	return nil
}

// displayUnsealInfo displays vault unseal information
func displayUnsealInfo(rc *eos_io.RuntimeContext, info *VaultInitInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Displaying vault unseal information")
	
	var unsealInfo strings.Builder
	unsealInfo.WriteString("\n🔓 Unseal Keys\n")
	
	if info.InitResponse != nil && len(info.InitResponse.Keys) > 0 {
		unsealInfo.WriteString(fmt.Sprintf("   Available: %d keys\n", len(info.InitResponse.Keys)))
		unsealInfo.WriteString("   Threshold: Configured via Vault policy\n")
		
		// Show masked keys for security
		for i, key := range info.InitResponse.Keys {
			unsealInfo.WriteString(fmt.Sprintf("   Key %d: %s\n", i+1, maskSensitiveData(key)))
		}
	} else {
		unsealInfo.WriteString("   No unseal keys available\n")
	}
	
	if _, err := fmt.Fprint(os.Stderr, unsealInfo.String()); err != nil {
		return fmt.Errorf("failed to display unseal info: %w", err)
	}
	
	return nil
}

// maskSensitiveData masks sensitive information for display
func maskSensitiveData(data string) string {
	if len(data) <= 8 {
		return strings.Repeat("*", len(data))
	}
	return data[:4] + strings.Repeat("*", len(data)-8) + data[len(data)-4:]
}

// TODO: The following helper functions and types would need to be defined:
// - VaultInitInfo struct
// - ReadInitOptions struct  
// - FileInfo, VaultStatus, RootToken, Mount, UnsealKey types
// These would be migrated from the original file or other related vault files