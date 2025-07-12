package vault

// Package vault provides secure vault display operations with structured logging
// This implementation follows Eos standards:
// - All user output uses fmt.Fprint(os.Stderr, ...) to preserve stdout
// - All debug/info logging uses otelzap.Ctx(rc.Ctx)
// - Follows Assess → Intervene → Evaluate pattern
// - Enhanced error handling and proper return values
// - Proper display formatting with structured builders

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
		
	// User notification via stderr
	if _, err := fmt.Fprintf(os.Stderr, "🔐 Vault init data exported securely to: %s\n", options.OutputPath); err != nil {
		return fmt.Errorf("failed to display export message: %w", err)
	}
	return nil
}

// DisplayStatusOnly displays only the status information without sensitive data
// Migrated from cmd/read/vault.go displayStatusOnly
func DisplayStatusOnly(rc *eos_io.RuntimeContext, info *VaultInitInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Prepare status display
	logger.Info("📊 Assessing status display requirements")
	
	// INTERVENE - Display formatted status information
	// User display via stderr
	if _, err := fmt.Fprint(os.Stderr, "\n🏛️ Vault Status Overview\n"); err != nil {
		return fmt.Errorf("failed to display header: %w", err)
	}
	if _, err := fmt.Fprint(os.Stderr, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"); err != nil {
		return fmt.Errorf("failed to display header: %w", err)
	}
	
	// Display file information
	if info.FileInfo != nil {
		// Display file info via stderr
		if _, err := fmt.Fprintf(os.Stderr, "\n📁 Init File: %s\n", info.FileInfo.Path); err != nil {
			return fmt.Errorf("failed to display file info: %w", err)
		}
		if _, err := fmt.Fprintf(os.Stderr, "   Exists: %v\n", info.FileInfo.Exists); err != nil {
			return fmt.Errorf("failed to display file info: %w", err)
		}
		if _, err := fmt.Fprintf(os.Stderr, "   Readable: %v\n", info.FileInfo.Readable); err != nil {
			return fmt.Errorf("failed to display file info: %w", err)
		}
		if info.FileInfo.Exists {
			if _, err := fmt.Fprintf(os.Stderr, "   Size: %d bytes\n", info.FileInfo.Size); err != nil {
				return fmt.Errorf("failed to display file info: %w", err)
			}
			if _, err := fmt.Fprintf(os.Stderr, "   Modified: %s\n", info.FileInfo.ModTime.Format("2006-01-02 15:04:05")); err != nil {
				return fmt.Errorf("failed to display file info: %w", err)
			}
		}
		
		logger.Debug("Displayed file information",
			zap.String("path", info.FileInfo.Path),
			zap.Bool("exists", info.FileInfo.Exists))
	}
	
	// Display Vault status
	if info.VaultStatus != nil {
		// Display vault status via stderr
		if _, err := fmt.Fprintf(os.Stderr, "\n🏛️ Vault Status\n"); err != nil {
			return fmt.Errorf("failed to display vault status: %w", err)
		}
		if _, err := fmt.Fprintf(os.Stderr, "   Address: %s\n", info.VaultStatus.Address); err != nil {
			return fmt.Errorf("failed to display vault status: %w", err)
		}
		if _, err := fmt.Fprintf(os.Stderr, "   Running: %v\n", info.VaultStatus.Running); err != nil {
			return fmt.Errorf("failed to display vault status: %w", err)
		}
		if _, err := fmt.Fprintf(os.Stderr, "   Reachable: %v\n", info.VaultStatus.Reachable); err != nil {
			return fmt.Errorf("failed to display vault status: %w", err)
		}
		if _, err := fmt.Fprintf(os.Stderr, "   Initialized: %v\n", info.VaultStatus.Initialized); err != nil {
			return fmt.Errorf("failed to display vault status: %w", err)
		}
		if _, err := fmt.Fprintf(os.Stderr, "   Sealed: %v\n", info.VaultStatus.Sealed); err != nil {
			return fmt.Errorf("failed to display vault status: %w", err)
		}
		if _, err := fmt.Fprintf(os.Stderr, "   Health: %s\n", info.VaultStatus.HealthStatus); err != nil {
			return fmt.Errorf("failed to display vault status: %w", err)
		}
		
		logger.Debug("Displayed vault status",
			zap.Bool("running", info.VaultStatus.Running),
			zap.Bool("sealed", info.VaultStatus.Sealed),
			zap.String("health", info.VaultStatus.HealthStatus))
	}
	
	// Display security status
	if info.SecurityStatus != nil {
		// Display security status via stderr
		if _, err := fmt.Fprintf(os.Stderr, "\n🔐 Security Status\n"); err != nil {
			return fmt.Errorf("failed to display security status: %w", err)
		}
		if _, err := fmt.Fprintf(os.Stderr, "   MFA Enabled: %v\n", info.SecurityStatus.MFAEnabled); err != nil {
			return fmt.Errorf("failed to display security status: %w", err)
		}
		if _, err := fmt.Fprintf(os.Stderr, "   Audit Enabled: %v\n", info.SecurityStatus.AuditEnabled); err != nil {
			return fmt.Errorf("failed to display security status: %w", err)
		}
		if _, err := fmt.Fprintf(os.Stderr, "   Hardening Applied: %v\n", info.SecurityStatus.HardeningApplied); err != nil {
			return fmt.Errorf("failed to display security status: %w", err)
		}
		if _, err := fmt.Fprintf(os.Stderr, "   Auth Methods: %d\n", len(info.SecurityStatus.AuthMethods)); err != nil {
			return fmt.Errorf("failed to display security status: %w", err)
		}
		
		logger.Debug("Displayed security status",
			zap.Bool("mfa_enabled", info.SecurityStatus.MFAEnabled),
			zap.Bool("audit_enabled", info.SecurityStatus.AuditEnabled),
			zap.Int("auth_methods", len(info.SecurityStatus.AuthMethods)))
	}
	
	// Display usage tip via stderr
	if _, err := fmt.Fprint(os.Stderr, "\n💡 Use --no-redact flag to view sensitive initialization data\n"); err != nil {
		return fmt.Errorf("failed to display usage tip: %w", err)
	}
	
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
	
	// INTERVENE - Display formatted agent status via stderr
	if _, err := fmt.Fprint(os.Stderr, "\n🤖 Vault Agent Status\n"); err != nil {
		return
	}
	if _, err := fmt.Fprint(os.Stderr, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"); err != nil {
		return
	}
	
	// Service status
	if status.ServiceRunning {
		fmt.Fprint(os.Stderr, "✅ Service: Running\n")
	} else {
		fmt.Fprint(os.Stderr, "❌ Service: Not Running\n")
	}
	
	// Token status
	if status.TokenAvailable {
		fmt.Fprint(os.Stderr, "✅ Token: Available\n")
		if !status.LastTokenTime.IsZero() {
			fmt.Fprintf(os.Stderr, "   Last Updated: %s\n", status.LastTokenTime.Format("2006-01-02 15:04:05"))
		}
		if status.TokenValid {
			fmt.Fprint(os.Stderr, "✅ Token: Valid\n")
		} else {
			fmt.Fprint(os.Stderr, "❌ Token: Invalid or Empty\n")
		}
	} else {
		fmt.Fprint(os.Stderr, "❌ Token: Not Available\n")
	}
	
	// Configuration status
	if status.ConfigValid {
		fmt.Fprint(os.Stderr, "✅ Configuration: Valid\n")
	} else {
		fmt.Fprint(os.Stderr, "❌ Configuration: Missing or Invalid\n")
	}
	
	// Overall health
	fmt.Fprint(os.Stderr, "\n🏥 Overall Health: ")
	switch status.HealthStatus {
	case "healthy":
		fmt.Fprint(os.Stderr, "✅ Healthy\n")
	case "degraded":
		fmt.Fprint(os.Stderr, "⚠️ Degraded\n")
	case "unhealthy":
		fmt.Fprint(os.Stderr, "❌ Unhealthy\n")
	default:
		fmt.Fprintf(os.Stderr, "❓ Unknown (%s)\n", status.HealthStatus)
	}
	
	// Recommendations
	if status.HealthStatus != "healthy" {
		fmt.Fprint(os.Stderr, "\n💡 Recommendations:\n")
		if !status.ServiceRunning {
			fmt.Fprint(os.Stderr, "   • Start the service: sudo systemctl start vault-agent-eos\n")
		}
		if !status.TokenAvailable || !status.TokenValid {
			fmt.Fprint(os.Stderr, "   • Check agent authentication: journalctl -fu vault-agent-eos\n")
		}
		if !status.ConfigValid {
			fmt.Fprint(os.Stderr, "   • Verify configuration: eos enable vault\n")
		}
	}
	
	// EVALUATE - Log display completion
	logger.Debug("Agent status displayed",
		zap.Bool("service_running", status.ServiceRunning),
		zap.Bool("token_valid", status.TokenValid),
		zap.String("health", status.HealthStatus))
}