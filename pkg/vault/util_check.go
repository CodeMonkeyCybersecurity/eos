package vault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.opentelemetry.io/otel/codes"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
)

func Check(rc *eos_io.RuntimeContext, client *api.Client, storedHashes []string, hashedRoot string) (*shared.CheckReport, *api.Client) {
	_, span := tracer.Start(context.Background(), "vault.Check")
	defer span.End()

	report := &shared.CheckReport{}

	if os.Getenv(shared.VaultAddrEnv) == "" {
		return failReport(rc, report, "VAULT_ADDR not set")
	}

	if healthy, err := CheckVaultHealth(rc); err != nil || !healthy {
		errMsg := fmt.Sprintf("Vault health check failed: %v", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, errMsg)
		return failReport(rc, report, errMsg)
	}

	if !isInstalled() {
		return failReport(rc, report, "Vault CLI binary not found in PATH")
	}
	report.Installed = true

	if client == nil {
		c, err := NewClient(rc)
		if err != nil {
			return failReport(rc, report, "Vault client initialization failed")
		}
		client = c
	}

	initStatus, err := IsVaultInitialized(client)
	if err != nil {
		errMsg := fmt.Sprintf("Init check error: %v", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, errMsg)
		return failReport(rc, report, errMsg)
	}
	report.Initialized = initStatus
	report.Sealed = IsVaultSealed(client)

	if report.Sealed {
		report.Notes = append(report.Notes, "Vault is sealed")
	}

	if len(storedHashes) > 0 && hashedRoot != "" && !verifyVaultSecrets(rc, storedHashes, hashedRoot) {
		report.Notes = append(report.Notes, "Vault secret mismatch or verification failed")
	}

	span.SetStatus(codes.Ok, "Vault check complete")
	return report, client
}

func failReport(rc *eos_io.RuntimeContext, r *shared.CheckReport, msg string) (*shared.CheckReport, *api.Client) {
	otelzap.Ctx(rc.Ctx).Warn("Vault check failed", zap.String("reason", msg))
	r.Notes = append(r.Notes, msg)
	return r, nil
}

func verifyVaultSecrets(rc *eos_io.RuntimeContext, storedHashes []string, hashedRoot string) bool {
	keys, root, err := PromptOrRecallUnsealKeys(rc)
	if err != nil || !crypto.AllUnique(keys) {
		return false
	}
	return crypto.AllHashesPresent(crypto.HashStrings(keys), storedHashes) &&
		crypto.HashString(root) == hashedRoot
}

func isInstalled() bool {
	_, err := exec.LookPath("vault")
	return err == nil
}

func IsVaultInitialized(client *api.Client) (bool, error) {
	status, err := client.Sys().Health()
	return err == nil && status.Initialized, err
}

func IsVaultSealed(client *api.Client) bool {
	status, err := client.Sys().Health()
	return err == nil && status.Sealed
}

func IsAlreadyInitialized(err error) bool {
	return strings.Contains(err.Error(), "Vault is already initialized")
}

func ListVault(rc *eos_io.RuntimeContext, path string) ([]string, error) {
	_, span := tracer.Start(context.Background(), "vault.ListVault")
	defer span.End()

	client, err := GetRootClient(rc)
	if err != nil {
		span.RecordError(err)
		return nil, cerr.Wrap(err, "get root client")
	}

	fullPath := shared.VaultSecretMountPath + path
	resp, err := client.Logical().List(fullPath)
	if err != nil || resp == nil {
		span.RecordError(err)
		return nil, cerr.Wrapf(err, "vault list failed at %s", fullPath)
	}

	rawKeys, _ := resp.Data["keys"].([]interface{})
	keys := make([]string, len(rawKeys))
	for i, k := range rawKeys {
		keys[i] = fmt.Sprintf("%v", k)
	}

	return keys, nil
}

func CheckVaultTokenFile() error {
	if _, err := os.Stat(shared.AgentToken); os.IsNotExist(err) {
		return cerr.Newf("vault agent token file missing: %s", shared.AgentToken)
	}
	return nil
}

// RunVaultTestQuery attempts a simple KVv2 read using the configured client.
func RunVaultTestQuery(rc *eos_io.RuntimeContext) error {
	client, err := GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}
	_, err = client.KVv2(shared.VaultSecretMount).Get(context.Background(), shared.TestKVPath)
	return err
}

func EnsureVaultReady(rc *eos_io.RuntimeContext) (*api.Client, error) {
	client, err := NewClient(rc)
	if err != nil {
		return nil, err
	}
	if err := probeVaultHealthUntilReady(rc, client); err == nil {
		return client, nil
	}
	if err := recoverVaultHealth(rc, client); err != nil {
		return nil, fmt.Errorf("vault recovery failed: %w", err)
	}
	return client, nil
}

// PathExistsKVv2 checks if a KV-v2 path has metadata.
func PathExistsKVv2(rc *eos_io.RuntimeContext, client *api.Client, mount, path string) (bool, error) {
	if client == nil {
		return false, fmt.Errorf("nil Vault client")
	}
	md, err := client.KVv2(mount).GetMetadata(rc.Ctx, path)
	switch {
	case err == nil && md != nil:
		otelzap.Ctx(rc.Ctx).Debug("✅ Metadata found", zap.String("mount", mount), zap.String("path", path))
		return true, nil
	case isNotFound(err):
		return false, nil
	default:
		otelzap.Ctx(rc.Ctx).Error("❌ Metadata check failed", zap.Error(err))
		return false, err
	}
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if respErr, ok := err.(*api.ResponseError); ok && respErr.StatusCode == 404 {
		return true
	}
	return strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "404")
}

// FindNextAvailableKVv2Path discovers an unused path under baseDir.
func FindNextAvailableKVv2Path(rc *eos_io.RuntimeContext, client *api.Client, mount, baseDir, leafBase string) (string, error) {
	listPath := fmt.Sprintf("%s/metadata/%s", mount, baseDir)

	sec, err := client.Logical().ListWithContext(rc.Ctx, listPath)
	if err != nil {
		if isNotFound(err) {
			return fmt.Sprintf("%s/%s", baseDir, leafBase), nil
		}
		return "", fmt.Errorf("listing metadata: %w", err)
	}
	if sec == nil || sec.Data == nil {
		return fmt.Sprintf("%s/%s", baseDir, leafBase), nil
	}

	rawKeys, _ := sec.Data["keys"].([]interface{})
	maxIdx := -1
	pattern := regexp.MustCompile(fmt.Sprintf(`^%s-(\d{3})$`, regexp.QuoteMeta(leafBase)))

	for _, v := range rawKeys {
		name := fmt.Sprintf("%v", v)
		switch {
		case name == leafBase:
			if maxIdx < 0 {
				maxIdx = 0
			}
		case pattern.MatchString(name):
			if parts := pattern.FindStringSubmatch(name); len(parts) == 2 {
				if idx, err := strconv.Atoi(parts[1]); err == nil && idx > maxIdx {
					maxIdx = idx
				}
			}
		}
	}

	nextIdx := maxIdx + 1
	var nextLeaf string
	if nextIdx == 0 {
		nextLeaf = leafBase
	} else {
		nextLeaf = fmt.Sprintf("%s-%03d", leafBase, nextIdx)
	}
	return fmt.Sprintf("%s/%s", baseDir, nextLeaf), nil
}

func CheckVaultAgentService() error {
	return exec.Command("systemctl", "is-active", "--quiet", shared.VaultAgentService).Run()
}
