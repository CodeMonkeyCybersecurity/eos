package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func PrintNextSteps(ctx context.Context) {
	logger := otelzap.Ctx(ctx)
	logger.Info("📋 Displaying Vault next steps")
	
	// Critical security warning - use stderr to ensure visibility
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "⚠️WARNING: You MUST securely back up the unseal keys and root token.")
	_, _ = fmt.Fprintln(os.Stderr, "WITHOUT THESE YOU CANNOT RECOVER YOUR VAULT.")
	
	_, _ = fmt.Fprintln(os.Stderr, "\n💾 These credentials have been saved to:")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "/var/lib/eos/secret/vault_init.json")
	
	_, _ = fmt.Fprintln(os.Stderr, "\nTo view them, run either:")
	_, _ = fmt.Fprintln(os.Stderr, "    sudo cat /var/lib/eos/secret/vault_init.json")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "    sudo eos read vault-init")
	_, _ = fmt.Fprintln(os.Stderr, "\n⚠️ Make sure no one is looking over your shoulder when you do this!")
	
	_, _ = fmt.Fprintln(os.Stderr, "\n➡️ NEXT STEPS:")
	_, _ = fmt.Fprintln(os.Stderr, "View and securely record the keys now. You will need them in the next step.")
	_, _ = fmt.Fprintln(os.Stderr, "Run:")
	_, _ = fmt.Fprintln(os.Stderr, "    sudo eos enable vault")
	
	_, _ = fmt.Fprintln(os.Stderr, "\nIMPORTANT: During enable, you will be asked to enter the root token and at least 3 of the unseal keys to complete the Vault setup.")
	
	_, _ = fmt.Fprintln(os.Stderr, "\n✅ Vault install complete — ready for enable phase.")
	_, _ = fmt.Fprintln(os.Stderr, "")
	
	logger.Info("✅ Vault next steps displayed", 
		zap.String("credential_location", "/var/lib/eos/secret/vault_init.json"),
		zap.String("next_command", "sudo eos enable vault"))
}

func PrintStorageSummary(ctx context.Context, primary string, primaryPath string, primaryResult string, fallback string, fallbackResult string) {
	logger := otelzap.Ctx(ctx)
	logger.Info("🔒 Displaying storage test summary",
		zap.String("primary", primary),
		zap.String("primary_result", primaryResult),
		zap.String("fallback", fallback), 
		zap.String("fallback_result", fallbackResult))
	
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "🔒 Test Data Storage Summary")
	_, _ = fmt.Fprintf(os.Stderr, "  %s: %s\n", primary, primaryResult)
	if primaryResult == "SUCCESS" {
		_, _ = fmt.Fprintf(os.Stderr, "    📂 Path: %s\n", primaryPath)
	}
	if fallback != "N/A" {
		_, _ = fmt.Fprintf(os.Stderr, "  %s: %s\n", fallback, fallbackResult)
		if fallbackResult == "SUCCESS" {
			_, _ = fmt.Fprintf(os.Stderr, "    📂 Path: %s\n", diskFallbackPath())
		}
	}
	_, _ = fmt.Fprintln(os.Stderr, "")
}

func PrintData(ctx context.Context, data map[string]interface{}, source, path string) {
	logger := otelzap.Ctx(ctx)
	logger.Info("🔒 Displaying test data contents",
		zap.String("source", source),
		zap.String("path", path),
		zap.Any("data", data))
	
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "🔒 Test Data Contents:")
	raw, _ := json.MarshalIndent(data, "", "  ")
	_, _ = fmt.Fprintln(os.Stderr, string(raw))
	_, _ = fmt.Fprintln(os.Stderr, "")

	PrintInspectSummary(ctx, source, path)
}

func PrintInspectSummary(ctx context.Context, source, path string) {
	logger := otelzap.Ctx(ctx)
	logger.Info("🔎 Displaying test data inspection summary",
		zap.String("source", source),
		zap.String("path", path))
	
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "🔎 Test Data Inspection Summary")
	switch source {
	case "Vault":
		_, _ = fmt.Fprintf(os.Stderr, "  🔐 Source: %s\n", source)
	case "Disk":
		_, _ = fmt.Fprintf(os.Stderr, "  💾 Source: %s\n", source)
	default:
		_, _ = fmt.Fprintf(os.Stderr, "  ❓ Source: %s\n", source)
	}
	_, _ = fmt.Fprintf(os.Stderr, "  📂 Path: %s\n", path)
	_, _ = fmt.Fprintln(os.Stderr, "")
}

// Backward compatibility functions (deprecated)

// PrintNextStepsCompat provides backward compatibility without context
// DEPRECATED: Use PrintNextSteps with context
func PrintNextStepsCompat() {
	PrintNextSteps(context.Background())
}

// PrintStorageSummaryCompat provides backward compatibility without context  
// DEPRECATED: Use PrintStorageSummary with context
func PrintStorageSummaryCompat(primary string, primaryPath string, primaryResult string, fallback string, fallbackResult string) {
	PrintStorageSummary(context.Background(), primary, primaryPath, primaryResult, fallback, fallbackResult)
}

// PrintDataCompat provides backward compatibility without context
// DEPRECATED: Use PrintData with context
func PrintDataCompat(data map[string]interface{}, source, path string) {
	PrintData(context.Background(), data, source, path)
}

// PrintInspectSummaryCompat provides backward compatibility without context
// DEPRECATED: Use PrintInspectSummary with context  
func PrintInspectSummaryCompat(source, path string) {
	PrintInspectSummary(context.Background(), source, path)
}

// Original function name aliases for backward compatibility
// These will be automatically used by existing callers

// Original PrintNextSteps without context - DEPRECATED
func PrintNextStepsOriginal() {
	PrintNextSteps(context.Background())
}

// Original PrintStorageSummary without context - DEPRECATED
func PrintStorageSummaryOriginal(primary string, primaryPath string, primaryResult string, fallback string, fallbackResult string) {
	PrintStorageSummary(context.Background(), primary, primaryPath, primaryResult, fallback, fallbackResult)
}

// Original PrintData without context - DEPRECATED
func PrintDataOriginal(data map[string]interface{}, source, path string) {
	PrintData(context.Background(), data, source, path)
}

// Original PrintInspectSummary without context - DEPRECATED  
func PrintInspectSummaryOriginal(source, path string) {
	PrintInspectSummary(context.Background(), source, path)
}
