package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func PrintNextSteps(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Displaying Vault next steps")

	// Critical security warning - use stderr to ensure visibility
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "WARNING: You MUST securely back up the unseal keys and root token.")
	_, _ = fmt.Fprintln(os.Stderr, "WITHOUT THESE YOU CANNOT RECOVER YOUR VAULT.")

	_, _ = fmt.Fprintln(os.Stderr, "\n These credentials have been saved to:")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "/var/lib/eos/secret/vault_init.json")

	_, _ = fmt.Fprintln(os.Stderr, "\nTo view them, run either:")
	_, _ = fmt.Fprintln(os.Stderr, "    sudo cat /var/lib/eos/secret/vault_init.json")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "    sudo eos read vault-init")
	_, _ = fmt.Fprintln(os.Stderr, "\nMake sure no one is looking over your shoulder when you do this!")

	_, _ = fmt.Fprintln(os.Stderr, "\n NEXT STEPS:")
	_, _ = fmt.Fprintln(os.Stderr, "View and securely record the keys now. You will need them in the next step.")
	_, _ = fmt.Fprintln(os.Stderr, "Run:")
	_, _ = fmt.Fprintln(os.Stderr, "    sudo eos enable vault")

	_, _ = fmt.Fprintln(os.Stderr, "\nIMPORTANT: During enable, you will be asked to enter the root token and at least 3 of the unseal keys to complete the Vault setup.")

	_, _ = fmt.Fprintln(os.Stderr, "\n Vault install complete — ready for enable phase.")
	_, _ = fmt.Fprintln(os.Stderr, "")

	logger.Info(" Vault next steps displayed",
		zap.String("credential_location", "/var/lib/eos/secret/vault_init.json"),
		zap.String("next_command", "sudo eos enable vault"))
}

func PrintStorageSummary(rc *eos_io.RuntimeContext, primary string, primaryPath string, primaryResult string, fallback string, fallbackResult string) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Displaying storage test summary",
		zap.String("primary", primary),
		zap.String("primary_result", primaryResult),
		zap.String("fallback", fallback),
		zap.String("fallback_result", fallbackResult))

	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, " Test Data Storage Summary")
	_, _ = fmt.Fprintf(os.Stderr, "  %s: %s\n", primary, primaryResult)
	if primaryResult == "SUCCESS" {
		_, _ = fmt.Fprintf(os.Stderr, "     Path: %s\n", primaryPath)
	}
	if fallback != "N/A" {
		_, _ = fmt.Fprintf(os.Stderr, "  %s: %s\n", fallback, fallbackResult)
		if fallbackResult == "SUCCESS" {
			_, _ = fmt.Fprintf(os.Stderr, "     Path: %s\n", diskFallbackPath())
		}
	}
	_, _ = fmt.Fprintln(os.Stderr, "")
}

func PrintData(rc *eos_io.RuntimeContext, data map[string]interface{}, source, path string) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Displaying test data contents",
		zap.String("source", source),
		zap.String("path", path),
		zap.Any("data", data))

	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, " Test Data Contents:")
	raw, _ := json.MarshalIndent(data, "", "  ")
	_, _ = fmt.Fprintln(os.Stderr, string(raw))
	_, _ = fmt.Fprintln(os.Stderr, "")

	PrintInspectSummary(rc, source, path)
}

func PrintInspectSummary(rc *eos_io.RuntimeContext, source, path string) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Displaying test data inspection summary",
		zap.String("source", source),
		zap.String("path", path))

	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, " Test Data Inspection Summary")
	switch source {
	case "Vault":
		_, _ = fmt.Fprintf(os.Stderr, "   Source: %s\n", source)
	case "Disk":
		_, _ = fmt.Fprintf(os.Stderr, "   Source: %s\n", source)
	default:
		_, _ = fmt.Fprintf(os.Stderr, "  ❓ Source: %s\n", source)
	}
	_, _ = fmt.Fprintf(os.Stderr, "   Path: %s\n", path)
	_, _ = fmt.Fprintln(os.Stderr, "")
}

// Backward compatibility functions (deprecated)

// PrintNextStepsCompat provides backward compatibility without RuntimeContext
// DEPRECATED: Use PrintNextSteps with RuntimeContext
func PrintNextStepsCompat() {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}
	PrintNextSteps(rc)
}

// PrintStorageSummaryCompat provides backward compatibility without RuntimeContext
// DEPRECATED: Use PrintStorageSummary with RuntimeContext
func PrintStorageSummaryCompat(primary string, primaryPath string, primaryResult string, fallback string, fallbackResult string) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}
	PrintStorageSummary(rc, primary, primaryPath, primaryResult, fallback, fallbackResult)
}

// PrintDataCompat provides backward compatibility without RuntimeContext
// DEPRECATED: Use PrintData with RuntimeContext
func PrintDataCompat(data map[string]interface{}, source, path string) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}
	PrintData(rc, data, source, path)
}

// PrintInspectSummaryCompat provides backward compatibility without RuntimeContext
// DEPRECATED: Use PrintInspectSummary with RuntimeContext
func PrintInspectSummaryCompat(source, path string) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}
	PrintInspectSummary(rc, source, path)
}

// Original function name aliases for backward compatibility
// These will be automatically used by existing callers

// Original PrintNextSteps without RuntimeContext - DEPRECATED
func PrintNextStepsOriginal() {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}
	PrintNextSteps(rc)
}

// Original PrintStorageSummary without RuntimeContext - DEPRECATED
func PrintStorageSummaryOriginal(primary string, primaryPath string, primaryResult string, fallback string, fallbackResult string) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}
	PrintStorageSummary(rc, primary, primaryPath, primaryResult, fallback, fallbackResult)
}

// Original PrintData without RuntimeContext - DEPRECATED
func PrintDataOriginal(data map[string]interface{}, source, path string) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}
	PrintData(rc, data, source, path)
}

// Original PrintInspectSummary without RuntimeContext - DEPRECATED
func PrintInspectSummaryOriginal(source, path string) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}
	PrintInspectSummary(rc, source, path)
}
