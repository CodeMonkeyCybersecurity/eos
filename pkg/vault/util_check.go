package vault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

func Check(client *api.Client, storedHashes []string, hashedRoot string) (*shared.CheckReport, *api.Client) {
	report := &shared.CheckReport{}

	// 1️⃣ Check VAULT_ADDR
	if os.Getenv(shared.VaultAddrEnv) == "" {
		return failReport(report, "VAULT_ADDR environment variable not set")
	}

	// 2️⃣ Check Vault health
	if healthy, err := CheckVaultHealth(); err != nil || !healthy {
		return failReport(report, fmt.Sprintf("Vault health check failed: %v", err))
	}

	// 3️⃣ Check vault binary
	if !isInstalled() {
		return failReport(report, "Vault binary not installed or not found in $PATH")
	}
	report.Installed = true

	// 4️⃣ Ensure client
	if client == nil {
		c, err := NewClient()
		if err != nil {
			return failReport(report, "Could not initialize Vault client")
		}
		client = c
	}

	// 5️⃣ Check initialized & sealed
	if ok, err := IsVaultInitialized(client); err == nil {
		report.Initialized = ok
	} else {
		return failReport(report, fmt.Sprintf("Vault init check failed: %v", err))
	}
	report.Sealed = IsVaultSealed(client)
	if report.Sealed {
		report.Notes = append(report.Notes, "Vault is sealed")
	}

	// 7️⃣ Verify secrets
	if len(storedHashes) > 0 && hashedRoot != "" && !verifyVaultSecrets(storedHashes, hashedRoot) {
		report.Notes = append(report.Notes, "Vault secret mismatch or verification failed")
	}

	return report, client
}

func failReport(r *shared.CheckReport, msg string) (*shared.CheckReport, *api.Client) {
	zap.L().Warn(msg)
	r.Notes = append(r.Notes, msg)
	return r, nil
}

func verifyVaultSecrets(storedHashes []string, hashedRoot string) bool {
	keys, root, err := PromptOrRecallUnsealKeys()
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

func ListVault(path string) ([]string, error) {
	client, err := GetRootClient()
	if err != nil {
		return nil, err
	}
	list, err := client.Logical().List(shared.VaultSecretMountPath + path)
	if err != nil || list == nil {
		return nil, err
	}
	rawKeys, _ := list.Data["keys"].([]interface{})
	keys := make([]string, len(rawKeys))
	for i, k := range rawKeys {
		keys[i] = fmt.Sprintf("%v", k)
	}
	return keys, nil
}

func CheckVaultAgentService() error {
	return exec.Command("systemctl", "is-active", "--quiet", shared.VaultAgentService).Run()
}

func CheckVaultTokenFile() error {
	if _, err := os.Stat(shared.AgentToken); os.IsNotExist(err) {
		return fmt.Errorf("vault token file not found at %s", shared.AgentToken)
	}
	return nil
}

func RunVaultTestQuery() error {
	cmd := exec.Command("vault", "kv", "get", "-format=json", shared.TestKVPath)
	cmd.Env = append(os.Environ(), "VAULT_TOKEN_PATH="+shared.AgentToken)
	return cmd.Run()
}

func EnsureVaultReady() (*api.Client, error) {
	client, err := NewClient()
	if err != nil {
		return nil, err
	}
	if err := probeVaultHealthUntilReady(client); err == nil {
		return client, nil
	}
	if err := recoverVaultHealth(client); err != nil {
		return nil, fmt.Errorf("vault recovery failed: %w", err)
	}
	return client, nil
}

// PathExistsKVv2 returns true if the KV-v2 metadata exists at mount/path,
// false if Vault reports a 404, or an error otherwise.
func PathExistsKVv2(client *api.Client, mount, path string) (bool, error) {
	if client == nil {
		return false, fmt.Errorf("vault client is nil")
	}

	// Use the GetMetadata helper (KVv2.GetMetadata) so we never read secret data.
	ctx := context.Background()
	md, err := client.KVv2(mount).GetMetadata(ctx, path)
	if err != nil {
		// 404 from the server → path does not exist
		if respErr, ok := err.(*api.ResponseError); ok && respErr.StatusCode == 404 {
			zap.L().Debug("📭 Vault KV-v2 metadata not found",
				zap.String("mount", mount),
				zap.String("path", path),
			)
			return false, nil
		}
		// Some backends may return plain-text errors containing "not found"
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "404") {
			zap.L().Debug("📭 Vault KV-v2 metadata not found (text match)",
				zap.String("mount", mount),
				zap.String("path", path),
			)
			return false, nil
		}
		// Anything else is unexpected
		zap.L().Error("❌ Unexpected error checking KV-v2 metadata",
			zap.String("mount", mount),
			zap.String("path", path),
			zap.Error(err),
		)
		return false, err
	}

	if md == nil {
		// no metadata → treat as not existing
		return false, nil
	}

	zap.L().Debug("✅ Vault KV-v2 metadata exists",
		zap.String("mount", mount),
		zap.String("path", path),
	)
	return true, nil
}

// FindNextAvailableKVv2Path returns the first path under baseDir of the form
//
//	baseDir/leafBase, baseDir/leafBase-001, baseDir/leafBase-002, ...
//
// whose metadata does *not* yet exist in the KV-v2 engine mounted at 'mount'.
func FindNextAvailableKVv2Path(
	client *api.Client,
	mount, baseDir, leafBase string,
) (string, error) {
	ctx := context.Background()

	// 1️⃣ List the existing entries under baseDir via the KV-v2 metadata endpoint
	listPath := fmt.Sprintf("%s/metadata/%s", mount, baseDir)
	sec, err := client.Logical().ListWithContext(ctx, listPath)
	if err != nil {
		// 404 → nothing there yet, just use the base leaf
		if respErr, ok := err.(*api.ResponseError); ok && respErr.StatusCode == 404 {
			return fmt.Sprintf("%s/%s", baseDir, leafBase), nil
		}
		return "", fmt.Errorf("listing KV-v2 metadata at %s: %w", listPath, err)
	}
	if sec == nil || sec.Data == nil {
		// no data → same as 404
		return fmt.Sprintf("%s/%s", baseDir, leafBase), nil
	}

	// 2️⃣ Extract the "keys" array
	rawKeys, _ := sec.Data["keys"].([]interface{})
	if len(rawKeys) == 0 {
		return fmt.Sprintf("%s/%s", baseDir, leafBase), nil
	}

	// 3️⃣ Scan for the highest numeric suffix
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
			parts := pattern.FindStringSubmatch(name)
			if idx, err := strconv.Atoi(parts[1]); err == nil && idx > maxIdx {
				maxIdx = idx
			}
		}
	}

	// 4️⃣ Next suffix
	nextIdx := maxIdx + 1
	var nextLeaf string
	if nextIdx == 0 {
		nextLeaf = leafBase
	} else {
		nextLeaf = fmt.Sprintf("%s-%03d", leafBase, nextIdx)
	}
	return fmt.Sprintf("%s/%s", baseDir, nextLeaf), nil
}
