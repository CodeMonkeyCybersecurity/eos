package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ExportToJSON exports VaultInitInfo to JSON format
// Migrated from cmd/read/vault.go exportToJSON
func ExportToJSON(rc *eos_io.RuntimeContext, info *VaultInitInfo, options *ReadInitOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Prepare JSON export
	logger.Info("📋 Assessing JSON export requirements",
		zap.String("output_path", options.OutputPath),
		zap.Bool("redacted", options.RedactSensitive))
	
	// INTERVENE - Marshal data to JSON
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		logger.Error("❌ Failed to marshal JSON", zap.Error(err))
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	
	// Handle output destination
	if options.OutputPath != "" {
		// Write to file
		if err := os.WriteFile(options.OutputPath, data, 0600); err != nil {
			logger.Error("❌ Failed to write JSON file", 
				zap.String("path", options.OutputPath),
				zap.Error(err))
			return err
		}
		logger.Info("✅ JSON exported to file successfully",
			zap.String("path", options.OutputPath),
			zap.Int("bytes", len(data)))
	} else {
		// Output to console
		fmt.Print(string(data))
		logger.Debug("JSON exported to console",
			zap.Int("bytes", len(data)))
	}
	
	// EVALUATE - Export completed successfully
	return nil
}

// ExportToSecureFile exports VaultInitInfo to a secure file with proper permissions
// Migrated from cmd/read/vault.go exportToSecureFile
func ExportToSecureFile(rc *eos_io.RuntimeContext, info *VaultInitInfo, options *ReadInitOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Validate requirements
	logger.Info("🔒 Assessing secure file export requirements",
		zap.String("output_path", options.OutputPath))
		
	if options.OutputPath == "" {
		return fmt.Errorf("output path required for secure export")
	}
	
	// INTERVENE - Create secure directory and file
	logger.Debug("Creating secure directory structure")
	
	// Create secure directory
	dir := filepath.Dir(options.OutputPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		logger.Error("❌ Failed to create output directory",
			zap.String("directory", dir),
			zap.Error(err))
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	
	// Marshal with indentation
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		logger.Error("❌ Failed to marshal JSON", zap.Error(err))
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	
	// Write with secure permissions
	if err := os.WriteFile(options.OutputPath, data, 0600); err != nil {
		logger.Error("❌ Failed to write secure file",
			zap.String("path", options.OutputPath),
			zap.Error(err))
		return fmt.Errorf("failed to write secure file: %w", err)
	}
	
	// EVALUATE - Log successful export
	logger.Info("✅ Vault init data exported securely",
		zap.String("path", options.OutputPath),
		zap.Int("bytes", len(data)),
		zap.String("permissions", "0600"))
		
	fmt.Printf("🔐 Vault init data exported securely to: %s\n", options.OutputPath)
	return nil
}

// DisplayStatusOnly displays only the status information without sensitive data
// Migrated from cmd/read/vault.go displayStatusOnly
func DisplayStatusOnly(rc *eos_io.RuntimeContext, info *VaultInitInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Prepare status display
	logger.Info("📊 Assessing status display requirements")
	
	// INTERVENE - Display formatted status information
	fmt.Println("\n🏛️ Vault Status Overview")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	
	// Display file information
	if info.FileInfo != nil {
		fmt.Printf("\n📁 Init File: %s\n", info.FileInfo.Path)
		fmt.Printf("   Exists: %v\n", info.FileInfo.Exists)
		fmt.Printf("   Readable: %v\n", info.FileInfo.Readable)
		if info.FileInfo.Exists {
			fmt.Printf("   Size: %d bytes\n", info.FileInfo.Size)
			fmt.Printf("   Modified: %s\n", info.FileInfo.ModTime.Format("2006-01-02 15:04:05"))
		}
		
		logger.Debug("Displayed file information",
			zap.String("path", info.FileInfo.Path),
			zap.Bool("exists", info.FileInfo.Exists))
	}
	
	// Display Vault status
	if info.VaultStatus != nil {
		fmt.Printf("\n🏛️ Vault Status\n")
		fmt.Printf("   Address: %s\n", info.VaultStatus.Address)
		fmt.Printf("   Running: %v\n", info.VaultStatus.Running)
		fmt.Printf("   Reachable: %v\n", info.VaultStatus.Reachable)
		fmt.Printf("   Initialized: %v\n", info.VaultStatus.Initialized)
		fmt.Printf("   Sealed: %v\n", info.VaultStatus.Sealed)
		fmt.Printf("   Health: %s\n", info.VaultStatus.HealthStatus)
		
		logger.Debug("Displayed vault status",
			zap.Bool("running", info.VaultStatus.Running),
			zap.Bool("sealed", info.VaultStatus.Sealed),
			zap.String("health", info.VaultStatus.HealthStatus))
	}
	
	// Display security status
	if info.SecurityStatus != nil {
		fmt.Printf("\n🔐 Security Status\n")
		fmt.Printf("   MFA Enabled: %v\n", info.SecurityStatus.MFAEnabled)
		fmt.Printf("   Audit Enabled: %v\n", info.SecurityStatus.AuditEnabled)
		fmt.Printf("   Hardening Applied: %v\n", info.SecurityStatus.HardeningApplied)
		fmt.Printf("   Auth Methods: %d\n", len(info.SecurityStatus.AuthMethods))
		
		logger.Debug("Displayed security status",
			zap.Bool("mfa_enabled", info.SecurityStatus.MFAEnabled),
			zap.Bool("audit_enabled", info.SecurityStatus.AuditEnabled),
			zap.Int("auth_methods", len(info.SecurityStatus.AuthMethods)))
	}
	
	fmt.Println("\n💡 Use --no-redact flag to view sensitive initialization data")
	
	// EVALUATE - Status display completed
	logger.Info("✅ Status display completed successfully")
	return nil
}

// DisplayAgentStatus provides human-readable display of Vault Agent status
// Migrated from cmd/read/vault.go displayAgentStatus
func DisplayAgentStatus(rc *eos_io.RuntimeContext, status *AgentStatus) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Prepare agent status display
	logger.Info("🤖 Assessing agent status display",
		zap.String("health", status.HealthStatus))
	
	// INTERVENE - Display formatted agent status
	fmt.Println("\n🤖 Vault Agent Status")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	
	// Service status
	if status.ServiceRunning {
		fmt.Println("✅ Service: Running")
	} else {
		fmt.Println("❌ Service: Not Running")
	}
	
	// Token status
	if status.TokenAvailable {
		fmt.Println("✅ Token: Available")
		if !status.LastTokenTime.IsZero() {
			fmt.Printf("   Last Updated: %s\n", status.LastTokenTime.Format("2006-01-02 15:04:05"))
		}
		if status.TokenValid {
			fmt.Println("✅ Token: Valid")
		} else {
			fmt.Println("❌ Token: Invalid or Empty")
		}
	} else {
		fmt.Println("❌ Token: Not Available")
	}
	
	// Configuration status
	if status.ConfigValid {
		fmt.Println("✅ Configuration: Valid")
	} else {
		fmt.Println("❌ Configuration: Missing or Invalid")
	}
	
	// Overall health
	fmt.Printf("\n🏥 Overall Health: ")
	switch status.HealthStatus {
	case "healthy":
		fmt.Println("✅ Healthy")
	case "degraded":
		fmt.Println("⚠️ Degraded")
	case "unhealthy":
		fmt.Println("❌ Unhealthy")
	default:
		fmt.Printf("❓ Unknown (%s)\n", status.HealthStatus)
	}
	
	// Recommendations
	if status.HealthStatus != "healthy" {
		fmt.Println("\n💡 Recommendations:")
		if !status.ServiceRunning {
			fmt.Println("   • Start the service: sudo systemctl start vault-agent-eos")
		}
		if !status.TokenAvailable || !status.TokenValid {
			fmt.Println("   • Check agent authentication: journalctl -fu vault-agent-eos")
		}
		if !status.ConfigValid {
			fmt.Println("   • Verify configuration: eos enable vault")
		}
	}
	
	// EVALUATE - Log display completion
	logger.Debug("Agent status displayed",
		zap.Bool("service_running", status.ServiceRunning),
		zap.Bool("token_valid", status.TokenValid),
		zap.String("health", status.HealthStatus))
}