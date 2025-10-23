package vault

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func PhaseEnsureVaultHealthy(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info(" [Phase 8] Ensuring Vault is ready")

	if isVaultProcessRunning(rc) {
		otelzap.Ctx(rc.Ctx).Info(" Vault process detected by lsof check")
	} else {
		otelzap.Ctx(rc.Ctx).Warn("Vault process NOT detected by lsof check")
	}

	if addr, err := EnsureVaultEnv(rc); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Could not resolve VAULT_ADDR", zap.Error(err))
		return fmt.Errorf("could not resolve VAULT_ADDR: %w", err)
	} else {
		otelzap.Ctx(rc.Ctx).Info(" VAULT_ADDR resolved", zap.String("address", addr))
	}

	client, err := GetPrivilegedClient(rc)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to create privileged Vault client", zap.Error(err))
		return fmt.Errorf("could not create Vault client: %w", err)
	}
	otelzap.Ctx(rc.Ctx).Info(" Privileged Vault client obtained")

	if err := probeVaultHealthUntilReady(rc, client); err == nil {
		otelzap.Ctx(rc.Ctx).Info(" Vault is healthy after probe")
		return nil
	}

	otelzap.Ctx(rc.Ctx).Warn("Vault did not become healthy after retries; escalate to phase 8")
	return err
}

func probeVaultHealthUntilReady(rc *eos_io.RuntimeContext, client *api.Client) error {
	for attempt := 1; attempt <= shared.VaultRetryCount; attempt++ {
		otelzap.Ctx(rc.Ctx).Info(" Vault health probe attempt", zap.Int("attempt", attempt))

		status, err := client.Sys().Health()
		if err != nil {
			otelzap.Ctx(rc.Ctx).Warn(" Vault health API error", zap.Int("attempt", attempt), zap.Error(err))
			// SECURITY P2 #7: Use context-aware sleep to respect cancellation
			if attempt < shared.VaultRetryCount {
				select {
				case <-time.After(shared.VaultRetryDelay):
					continue
				case <-rc.Ctx.Done():
					return fmt.Errorf("vault health check cancelled: %w", rc.Ctx.Err())
				}
			}
			continue
		}

		otelzap.Ctx(rc.Ctx).Debug(" Vault health status",
			zap.Bool("initialized", status.Initialized),
			zap.Bool("sealed", status.Sealed),
			zap.Bool("standby", status.Standby),
		)

		if !status.Initialized {
			otelzap.Ctx(rc.Ctx).Error(" Vault uninitialized; deferring to phase 8")
			return fmt.Errorf("vault uninitialized; defer to phase 8")
		}
		if status.Initialized && status.Sealed {
			otelzap.Ctx(rc.Ctx).Error(" Vault sealed; deferring to phase 8")
			return fmt.Errorf("vault sealed; defer to phase 8")
		}

		if !status.Sealed && !status.Standby {
			otelzap.Ctx(rc.Ctx).Info(" Vault is unsealed and active")
			return nil
		}
		if status.Standby {
			otelzap.Ctx(rc.Ctx).Info("🟡 Vault is in standby — treating as healthy")
			return nil
		}

		otelzap.Ctx(rc.Ctx).Warn("Unexpected Vault health state", zap.Any("response", status))
		// SECURITY P2 #7: Use context-aware sleep to respect cancellation
		if attempt < shared.VaultRetryCount {
			select {
			case <-time.After(shared.VaultRetryDelay):
				// Continue to next health check
			case <-rc.Ctx.Done():
				return fmt.Errorf("vault health check cancelled: %w", rc.Ctx.Err())
			}
		}
	}
	otelzap.Ctx(rc.Ctx).Error(" Vault not healthy after maximum retry attempts",
		zap.Int("retries", shared.VaultRetryCount))
	return fmt.Errorf("vault not healthy after %d attempts", shared.VaultRetryCount)
}

func CheckVaultHealth(rc *eos_io.RuntimeContext) (bool, error) {
	addr := os.Getenv(shared.VaultAddrEnv)
	if addr == "" {
		otelzap.Ctx(rc.Ctx).Error(" VAULT_ADDR environment variable not set")
		return false, fmt.Errorf("VAULT_ADDR not set")
	}

	url := strings.TrimRight(addr, "/") + shared.VaultHealthPath
	otelzap.Ctx(rc.Ctx).Debug(" Performing raw Vault health check", zap.String("url", url))

	// Create HTTP client with timeout to prevent indefinite hangs
	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to create Vault health request", zap.Error(err))
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	// DEVELOPMENT: Skip TLS verification for self-signed certificates
	// In development environments, Vault uses self-signed certificates that won't be in the system trust store
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // #nosec G402 - Development environment with self-signed certificates
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Vault health endpoint not responding", zap.String("url", url), zap.Error(err))
		return false, fmt.Errorf("vault not responding: %w", err)
	}
	defer shared.SafeClose(rc.Ctx, resp.Body)

	otelzap.Ctx(rc.Ctx).Debug(" Vault health HTTP response", zap.Int("statusCode", resp.StatusCode))

	switch resp.StatusCode {
	case 200, 429:
		otelzap.Ctx(rc.Ctx).Info(" Vault is healthy or throttled", zap.Int("statusCode", resp.StatusCode))
		return true, nil
	case 501, 503:
		otelzap.Ctx(rc.Ctx).Warn("Vault is not initialized or unavailable", zap.Int("statusCode", resp.StatusCode))
		return false, nil
	default:
		body, _ := io.ReadAll(resp.Body)
		otelzap.Ctx(rc.Ctx).Error(" Unexpected Vault health response",
			zap.Int("statusCode", resp.StatusCode),
			zap.ByteString("body", body))
		return false, fmt.Errorf("unexpected vault health: %s", body)
	}
}

func isVaultProcessRunning(rc *eos_io.RuntimeContext) bool {
	otelzap.Ctx(rc.Ctx).Debug(" Checking Vault process using lsof")
	out, err := exec.Command("lsof", "-i", shared.VaultDefaultPort).Output()
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("lsof command failed (process check skipped)", zap.Error(err))
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		// Check for vault process running as vault user
		if strings.Contains(line, "vault") && strings.Contains(line, ":"+shared.VaultDefaultPort) {
			otelzap.Ctx(rc.Ctx).Debug(" Vault process detected in lsof output", zap.String("line", line))
			return true
		}
	}
	otelzap.Ctx(rc.Ctx).Warn("Vault process not found in lsof output")
	return false
}

func ValidateAndCache(rc *eos_io.RuntimeContext, client *api.Client) {
	otelzap.Ctx(rc.Ctx).Info(" Validating and caching Vault client")
	report, checked := Check(rc, client, nil, "")
	if checked != nil {
		otelzap.Ctx(rc.Ctx).Info(" Caching validated Vault client")
		SetVaultClient(rc, checked)
	}
	if report == nil {
		otelzap.Ctx(rc.Ctx).Warn("Vault check returned nil — skipping further setup")
		return
	}
	for _, note := range report.Notes {
		otelzap.Ctx(rc.Ctx).Warn("Vault diagnostic note", zap.String("note", note))
	}
}
