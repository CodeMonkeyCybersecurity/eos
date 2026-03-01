package mattermost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// --- Test helpers ---

// testRC creates a minimal RuntimeContext for testing.
func testRC() *eos_io.RuntimeContext {
	return &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}
}

// noopInstaller returns an installer where all operations succeed.
func noopInstaller() *installer {
	return &installer{
		checkDocker:     func(_ *eos_io.RuntimeContext) error { return nil },
		gitClone:        func(_, _ string) error { return nil },
		mkdirP:          func(_ *eos_io.RuntimeContext, _ string, _ os.FileMode) error { return nil },
		copyR:           func(_ *eos_io.RuntimeContext, _, _ string) error { return nil },
		removeAll:       func(_ string) error { return nil },
		chown:           func(_, _ string) error { return nil },
		ensureNetwork:   func(_ *eos_io.RuntimeContext) error { return nil },
		composeUp:       func(_ *eos_io.RuntimeContext, _ string) error { return nil },
		checkContainers: func(_ *eos_io.RuntimeContext) error { return nil },
		stat:            func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		readFile:        func(_ string) ([]byte, error) { return nil, os.ErrNotExist },
		writeFile:       func(_ string, _ []byte, _ os.FileMode) error { return nil },
		patchEnvFile:    func(_ string, _ map[string]string) error { return nil },
		mkdirAll:        func(_ string, _ os.FileMode) error { return nil },
	}
}

// --- Unit tests: InstallConfig ---

func TestDefaultInstallConfig(t *testing.T) {
	cfg := DefaultInstallConfig()

	if cfg.Port != DefaultPort {
		t.Errorf("default port = %d, want %d", cfg.Port, DefaultPort)
	}
	if cfg.SupportEmail != DefaultSupportEmail {
		t.Errorf("default support email = %q, want %q", cfg.SupportEmail, DefaultSupportEmail)
	}
	if cfg.PostgresPassword != "" {
		t.Error("default postgres password should be empty (auto-generated)")
	}
	if cfg.DryRun {
		t.Error("default DryRun should be false")
	}
}

func TestInstallConfigValidate_ValidConfig(t *testing.T) {
	cfg := DefaultInstallConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid config should not error: %v", err)
	}
}

func TestInstallConfigValidate_InvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"zero", 0},
		{"negative", -1},
		{"too_high", 65536},
		{"way_too_high", 100000},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultInstallConfig()
			cfg.Port = tc.port
			if err := cfg.Validate(); err == nil {
				t.Errorf("port %d should fail validation", tc.port)
			}
		})
	}
}

func TestInstallConfigValidate_ValidPorts(t *testing.T) {
	validPorts := []int{1, 80, 443, 8017, 8065, 65535}
	for _, port := range validPorts {
		cfg := DefaultInstallConfig()
		cfg.Port = port
		if err := cfg.Validate(); err != nil {
			t.Errorf("port %d should be valid: %v", port, err)
		}
	}
}

// --- Unit tests: actionDescription ---

func TestActionDescription(t *testing.T) {
	fresh := actionDescription(false)
	if !strings.Contains(fresh, "fresh") {
		t.Errorf("fresh install description should mention 'fresh', got %q", fresh)
	}

	existing := actionDescription(true)
	if !strings.Contains(existing, "update") {
		t.Errorf("existing deployment description should mention 'update', got %q", existing)
	}
}

// --- Unit tests: isAlreadyDeployedWith ---

func TestIsAlreadyDeployedWith_NotDeployed(t *testing.T) {
	ins := noopInstaller()
	ins.stat = func(_ string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	if isAlreadyDeployedWith(ins) {
		t.Error("should return false when compose file doesn't exist")
	}
}

func TestIsAlreadyDeployedWith_Deployed(t *testing.T) {
	ins := noopInstaller()
	ins.stat = func(_ string) (os.FileInfo, error) {
		return nil, nil // exists
	}
	if !isAlreadyDeployedWith(ins) {
		t.Error("should return true when compose file exists")
	}
}

// --- Unit tests: installWith (full pipeline) ---

func TestInstallWith_FreshInstall(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()
	cfg.PostgresPassword = "test-password"

	ins := noopInstaller()

	var cloned, mkdird, copied, chowned, networked, composed, checked bool

	ins.gitClone = func(url, _ string) error {
		if url != RepoURL {
			t.Errorf("unexpected clone URL: %s", url)
		}
		cloned = true
		return nil
	}
	ins.mkdirP = func(_ *eos_io.RuntimeContext, _ string, _ os.FileMode) error {
		mkdird = true
		return nil
	}
	ins.copyR = func(_ *eos_io.RuntimeContext, _, _ string) error {
		copied = true
		return nil
	}
	ins.stat = func(path string) (os.FileInfo, error) {
		return nil, os.ErrNotExist // nothing exists
	}
	ins.readFile = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, EnvExampleFileName) {
			return []byte("DOMAIN=example.com\nPORT=8065\n"), nil
		}
		return nil, os.ErrNotExist
	}
	ins.writeFile = func(_ string, _ []byte, _ os.FileMode) error {
		return nil
	}
	ins.chown = func(_, _ string) error {
		chowned = true
		return nil
	}
	ins.ensureNetwork = func(_ *eos_io.RuntimeContext) error {
		networked = true
		return nil
	}
	ins.composeUp = func(_ *eos_io.RuntimeContext, _ string) error {
		composed = true
		return nil
	}
	ins.checkContainers = func(_ *eos_io.RuntimeContext) error {
		checked = true
		return nil
	}

	if err := installWith(rc, cfg, ins); err != nil {
		t.Fatalf("installWith failed: %v", err)
	}

	if !cloned {
		t.Error("git clone was not called for fresh install")
	}
	if !mkdird {
		t.Error("mkdirP was not called")
	}
	if !copied {
		t.Error("copyR was not called")
	}
	if !chowned {
		t.Error("chown was not called")
	}
	if !networked {
		t.Error("ensureNetwork was not called")
	}
	if !composed {
		t.Error("composeUp was not called")
	}
	if !checked {
		t.Error("checkContainers was not called")
	}
}

func TestInstallWith_ExistingDeployment(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()
	cfg.PostgresPassword = "test-password"

	ins := noopInstaller()
	var cloned bool
	ins.gitClone = func(_, _ string) error {
		cloned = true
		return nil
	}

	ins.stat = func(path string) (os.FileInfo, error) {
		if strings.HasSuffix(path, ComposeFileName) {
			return nil, nil // exists
		}
		if strings.HasSuffix(path, EnvFileName) {
			return nil, nil // .env exists too
		}
		return nil, os.ErrNotExist
	}

	if err := installWith(rc, cfg, ins); err != nil {
		t.Fatalf("installWith failed: %v", err)
	}

	if cloned {
		t.Error("git clone should NOT be called for existing deployment")
	}
}

func TestInstallWith_DryRun(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()
	cfg.DryRun = true

	ins := noopInstaller()
	var composed bool
	ins.composeUp = func(_ *eos_io.RuntimeContext, _ string) error {
		composed = true
		return nil
	}

	if err := installWith(rc, cfg, ins); err != nil {
		t.Fatalf("dry run should not error: %v", err)
	}

	if composed {
		t.Error("composeUp should NOT be called during dry run")
	}
}

func TestInstallWith_DryRunAlreadyDeployed(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()
	cfg.DryRun = true

	ins := noopInstaller()
	ins.stat = func(path string) (os.FileInfo, error) {
		if strings.HasSuffix(path, ComposeFileName) {
			return nil, nil // exists
		}
		return nil, os.ErrNotExist
	}

	if err := installWith(rc, cfg, ins); err != nil {
		t.Fatalf("dry run with existing deployment should not error: %v", err)
	}
}

func TestInstallWith_InvalidConfig(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()
	cfg.Port = -1

	ins := noopInstaller()

	if err := installWith(rc, cfg, ins); err == nil {
		t.Error("should fail with invalid port")
	}
}

func TestInstallWith_DockerNotInstalled(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()

	ins := noopInstaller()
	ins.checkDocker = func(_ *eos_io.RuntimeContext) error {
		return errors.New("docker not found")
	}

	err := installWith(rc, cfg, ins)
	if err == nil {
		t.Fatal("should fail when docker is not installed")
	}
	if !strings.Contains(err.Error(), "docker is required") {
		t.Errorf("error should mention docker requirement, got: %v", err)
	}
}

func TestInstallWith_CloneFails(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()

	ins := noopInstaller()
	ins.gitClone = func(_, _ string) error {
		return errors.New("network unreachable")
	}

	err := installWith(rc, cfg, ins)
	if err == nil {
		t.Fatal("should fail when clone fails")
	}
	if !strings.Contains(err.Error(), "git clone failed") {
		t.Errorf("error should mention git clone failure, got: %v", err)
	}
}

func TestInstallWith_MkdirFails(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()

	ins := noopInstaller()
	ins.mkdirP = func(_ *eos_io.RuntimeContext, _ string, _ os.FileMode) error {
		return errors.New("permission denied")
	}

	err := installWith(rc, cfg, ins)
	if err == nil {
		t.Fatal("should fail when mkdir fails")
	}
	if !strings.Contains(err.Error(), "install directory") {
		t.Errorf("error should mention install directory, got: %v", err)
	}
}

func TestInstallWith_CopyFails(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()

	ins := noopInstaller()
	ins.copyR = func(_ *eos_io.RuntimeContext, _, _ string) error {
		return errors.New("disk full")
	}

	err := installWith(rc, cfg, ins)
	if err == nil {
		t.Fatal("should fail when copy fails")
	}
	if !strings.Contains(err.Error(), "copy files") {
		t.Errorf("error should mention copy failure, got: %v", err)
	}
}

func TestInstallWith_ChownFails(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()

	ins := noopInstaller()
	ins.readFile = func(_ string) ([]byte, error) {
		return []byte("DOMAIN=x\n"), nil
	}
	ins.chown = func(_, _ string) error {
		return errors.New("operation not permitted")
	}

	err := installWith(rc, cfg, ins)
	if err == nil {
		t.Fatal("should fail when chown fails")
	}
	if !strings.Contains(err.Error(), "volume ownership") {
		t.Errorf("error should mention volume ownership, got: %v", err)
	}
}

func TestInstallWith_ComposeUpFails(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()

	ins := noopInstaller()
	ins.readFile = func(_ string) ([]byte, error) {
		return []byte("DOMAIN=x\n"), nil
	}
	ins.composeUp = func(_ *eos_io.RuntimeContext, _ string) error {
		return errors.New("compose failed")
	}

	err := installWith(rc, cfg, ins)
	if err == nil {
		t.Fatal("should fail when compose up fails")
	}
	if !strings.Contains(err.Error(), "deploy containers") {
		t.Errorf("error should mention container deployment, got: %v", err)
	}
}

func TestInstallWith_ContainerCheckWarningNonFatal(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()

	ins := noopInstaller()
	ins.readFile = func(_ string) ([]byte, error) {
		return []byte("DOMAIN=x\n"), nil
	}
	ins.checkContainers = func(_ *eos_io.RuntimeContext) error {
		return errors.New("some containers unhealthy")
	}

	if err := installWith(rc, cfg, ins); err != nil {
		t.Fatalf("container check warning should be non-fatal: %v", err)
	}
}

func TestInstallWith_NetworkFailureNonFatal(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()

	ins := noopInstaller()
	ins.readFile = func(_ string) ([]byte, error) {
		return []byte("DOMAIN=x\n"), nil
	}
	ins.ensureNetwork = func(_ *eos_io.RuntimeContext) error {
		return errors.New("network creation failed")
	}

	if err := installWith(rc, cfg, ins); err != nil {
		t.Fatalf("network failure should be non-fatal: %v", err)
	}
}

func TestInstallWith_EnvExampleReadFails(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()

	ins := noopInstaller()
	ins.readFile = func(_ string) ([]byte, error) {
		return nil, errors.New("file not found")
	}

	err := installWith(rc, cfg, ins)
	if err == nil {
		t.Fatal("should fail when env.example can't be read")
	}
}

func TestInstallWith_EnvWriteFails(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()

	ins := noopInstaller()
	ins.readFile = func(_ string) ([]byte, error) {
		return []byte("DOMAIN=x\n"), nil
	}
	ins.writeFile = func(_ string, _ []byte, _ os.FileMode) error {
		return errors.New("disk full")
	}

	err := installWith(rc, cfg, ins)
	if err == nil {
		t.Fatal("should fail when .env can't be written")
	}
}

// --- Unit tests: patchEnvInPlace ---

func TestInstallWith_ExistingDeployment_PatchFails(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()
	cfg.PostgresPassword = "test-password"

	ins := noopInstaller()
	ins.stat = func(path string) (os.FileInfo, error) {
		if strings.HasSuffix(path, ComposeFileName) {
			return nil, nil // compose exists = already deployed
		}
		if strings.HasSuffix(path, EnvFileName) {
			return nil, os.ErrNotExist // .env doesn't exist
		}
		return nil, os.ErrNotExist
	}
	ins.readFile = func(_ string) ([]byte, error) {
		return nil, errors.New("env.example missing")
	}

	err := installWith(rc, cfg, ins)
	if err == nil {
		t.Fatal("should fail when existing deployment patch fails")
	}
	if !strings.Contains(err.Error(), "update configuration") {
		t.Errorf("error should mention update configuration, got: %v", err)
	}
}

func TestInstallWith_VolumeMkdirAllFails(t *testing.T) {
	rc := testRC()
	cfg := DefaultInstallConfig()

	ins := noopInstaller()
	ins.readFile = func(_ string) ([]byte, error) {
		return []byte("DOMAIN=x\n"), nil
	}
	ins.mkdirAll = func(_ string, _ os.FileMode) error {
		return errors.New("permission denied")
	}

	err := installWith(rc, cfg, ins)
	if err == nil {
		t.Fatal("should fail when volume mkdirAll fails")
	}
	if !strings.Contains(err.Error(), "volume") {
		t.Errorf("error should mention volume, got: %v", err)
	}
}

func TestPatchEnvInPlace_Basic(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, ".env")

	content := "DOMAIN=old.example.com\nPORT=8065\nOTHER=keep\n"
	if err := os.WriteFile(envPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test .env: %v", err)
	}

	updates := map[string]string{
		"DOMAIN": "localhost",
		"PORT":   "8017",
	}

	if err := patchEnvInPlace(envPath, updates); err != nil {
		t.Fatalf("patchEnvInPlace failed: %v", err)
	}

	result, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read patched .env: %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "DOMAIN=localhost") {
		t.Error("DOMAIN should be patched to 'localhost'")
	}
	if !strings.Contains(resultStr, "PORT=8017") {
		t.Error("PORT should be patched to '8017'")
	}
	if !strings.Contains(resultStr, "OTHER=keep") {
		t.Error("OTHER should be preserved")
	}
}

func TestPatchEnvInPlace_CommentedKeys(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, ".env")

	content := "#DOMAIN=localhost\n#PORT=8065\nACTIVE=yes\n"
	if err := os.WriteFile(envPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test .env: %v", err)
	}

	updates := map[string]string{
		"DOMAIN": "chat.example.com",
		"PORT":   "8017",
	}

	if err := patchEnvInPlace(envPath, updates); err != nil {
		t.Fatalf("patchEnvInPlace failed: %v", err)
	}

	result, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read patched .env: %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "DOMAIN=chat.example.com") {
		t.Errorf("commented DOMAIN should be patched, got: %s", resultStr)
	}
	if !strings.Contains(resultStr, "PORT=8017") {
		t.Errorf("commented PORT should be patched, got: %s", resultStr)
	}
	if strings.Contains(resultStr, "#DOMAIN") {
		t.Error("patched DOMAIN should not be commented")
	}
}

func TestPatchEnvInPlace_MissingKeysAppended(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, ".env")

	content := "EXISTING=value\n"
	if err := os.WriteFile(envPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test .env: %v", err)
	}

	updates := map[string]string{
		"NEWKEY": "newvalue",
	}

	if err := patchEnvInPlace(envPath, updates); err != nil {
		t.Fatalf("patchEnvInPlace should append missing keys: %v", err)
	}

	result, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}
	resultStr := string(result)
	if !strings.Contains(resultStr, "EXISTING=value") {
		t.Error("existing content should be preserved")
	}
	if !strings.Contains(resultStr, "NEWKEY=newvalue") {
		t.Error("missing key should be appended")
	}
}

func TestPatchEnvInPlace_EmptyFile_AppendsKeys(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, ".env")

	if err := os.WriteFile(envPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write empty .env: %v", err)
	}

	updates := map[string]string{"KEY": "value"}
	if err := patchEnvInPlace(envPath, updates); err != nil {
		t.Fatalf("patchEnvInPlace should handle empty file: %v", err)
	}

	result, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}
	if !strings.Contains(string(result), "KEY=value") {
		t.Error("key should be appended to empty file")
	}
}

func TestPatchEnvInPlace_NonexistentFile(t *testing.T) {
	err := patchEnvInPlace("/nonexistent/path/.env", map[string]string{"KEY": "val"})
	if err == nil {
		t.Error("should error on nonexistent file")
	}
}

func TestPatchEnvInPlace_PreservesBlankLines(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, ".env")

	content := "FIRST=one\n\nSECOND=two\n\n# comment\nTHIRD=three\n"
	if err := os.WriteFile(envPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	updates := map[string]string{"SECOND": "patched"}
	if err := patchEnvInPlace(envPath, updates); err != nil {
		t.Fatalf("patchEnvInPlace failed: %v", err)
	}

	result, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "SECOND=patched") {
		t.Error("SECOND should be patched")
	}
	if !strings.Contains(resultStr, "FIRST=one") {
		t.Error("FIRST should be preserved")
	}
	if !strings.Contains(resultStr, "THIRD=three") {
		t.Error("THIRD should be preserved")
	}
}

func TestPatchEnvInPlace_EqualsInValue(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, ".env")

	content := "DSN=postgres://user:pass@host:5432/db?ssl=true\nOTHER=val\n"
	if err := os.WriteFile(envPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	updates := map[string]string{"OTHER": "new_val"}
	if err := patchEnvInPlace(envPath, updates); err != nil {
		t.Fatalf("patchEnvInPlace failed: %v", err)
	}

	result, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "DSN=postgres://user:pass@host:5432/db?ssl=true") {
		t.Errorf("DSN with = in value should be preserved, got: %s", resultStr)
	}
	if !strings.Contains(resultStr, "OTHER=new_val") {
		t.Error("OTHER should be patched")
	}
}

// --- Unit tests: PatchMattermostEnv ---

func TestPatchMattermostEnv_NoEnvExample(t *testing.T) {
	tmpDir := t.TempDir()
	err := PatchMattermostEnv(tmpDir)
	if err == nil {
		t.Error("should error when env.example doesn't exist and .env doesn't exist")
	}
}

func TestPatchMattermostEnv_CreatesEnvFromExample(t *testing.T) {
	tmpDir := t.TempDir()

	exampleContent := "DOMAIN=example.com\nPORT=8065\nTZ=America/New_York\n"
	if err := os.WriteFile(filepath.Join(tmpDir, EnvExampleFileName), []byte(exampleContent), 0644); err != nil {
		t.Fatalf("failed to create env.example: %v", err)
	}

	if err := PatchMattermostEnv(tmpDir); err != nil {
		t.Fatalf("PatchMattermostEnv failed: %v", err)
	}

	envPath := filepath.Join(tmpDir, EnvFileName)
	result, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "DOMAIN=localhost") {
		t.Errorf("DOMAIN should be overridden to 'localhost', got: %s", resultStr)
	}
	if !strings.Contains(resultStr, "TZ=UTC") {
		t.Errorf("TZ should be overridden to 'UTC', got: %s", resultStr)
	}
}

func TestPatchMattermostEnv_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()

	exampleContent := "DOMAIN=example.com\nPORT=8065\n"
	if err := os.WriteFile(filepath.Join(tmpDir, EnvExampleFileName), []byte(exampleContent), 0644); err != nil {
		t.Fatalf("failed to create env.example: %v", err)
	}

	if err := PatchMattermostEnv(tmpDir); err != nil {
		t.Fatalf("first PatchMattermostEnv failed: %v", err)
	}
	if err := PatchMattermostEnv(tmpDir); err != nil {
		t.Fatalf("second PatchMattermostEnv failed: %v", err)
	}

	result, err := os.ReadFile(filepath.Join(tmpDir, EnvFileName))
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}

	resultStr := string(result)
	if strings.Count(resultStr, "DOMAIN=") != 1 {
		t.Errorf("DOMAIN should appear exactly once, got: %s", resultStr)
	}
}

func TestPatchEnvInPlace_ExportedMatchesInternal(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, ".env")

	content := "KEY=old\n"
	if err := os.WriteFile(envPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	if err := PatchEnvInPlace(envPath, map[string]string{"KEY": "new"}); err != nil {
		t.Fatalf("PatchEnvInPlace failed: %v", err)
	}

	result, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}
	if !strings.Contains(string(result), "KEY=new") {
		t.Error("exported PatchEnvInPlace should work like internal version")
	}
}

func TestPatchMattermostEnv_ExistingEnvPreserved(t *testing.T) {
	tmpDir := t.TempDir()

	exampleContent := "DOMAIN=from_example\nPORT=8065\n"
	existingEnv := "DOMAIN=from_existing\nPORT=9999\n"
	if err := os.WriteFile(filepath.Join(tmpDir, EnvExampleFileName), []byte(exampleContent), 0644); err != nil {
		t.Fatalf("failed to create env.example: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, EnvFileName), []byte(existingEnv), 0644); err != nil {
		t.Fatalf("failed to create .env: %v", err)
	}

	if err := PatchMattermostEnv(tmpDir); err != nil {
		t.Fatalf("PatchMattermostEnv failed: %v", err)
	}

	result, err := os.ReadFile(filepath.Join(tmpDir, EnvFileName))
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "DOMAIN=localhost") {
		t.Errorf("DOMAIN should be overridden to 'localhost', got: %s", resultStr)
	}
}

// --- Unit tests: patchEnvWith ---

func TestPatchEnvWith_ExistingEnvFile(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, EnvFileName)
	envContent := "DOMAIN=old\nPORT=8065\nPOSTGRES_PASSWORD=old\n"
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	overrides := map[string]string{
		"PORT":              fmt.Sprintf("%d", 8017),
		"POSTGRES_PASSWORD": "secret",
	}

	if err := PatchEnvInPlace(envPath, overrides); err != nil {
		t.Fatalf("PatchEnvInPlace failed: %v", err)
	}

	result, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "PORT=8017") {
		t.Error("PORT should be patched to 8017")
	}
	if !strings.Contains(resultStr, "POSTGRES_PASSWORD=secret") {
		t.Error("POSTGRES_PASSWORD should be patched")
	}
}
