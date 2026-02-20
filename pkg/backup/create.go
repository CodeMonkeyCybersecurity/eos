// pkg/backup/create.go

package backup

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

var secretsDirPath = SecretsDir

func CreateRepository(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	name := args[0]
	backend, _ := cmd.Flags().GetString("backend")
	url, _ := cmd.Flags().GetString("url")
	path, _ := cmd.Flags().GetString("path")
	envVars, _ := cmd.Flags().GetStringSlice("env")
	doInit, _ := cmd.Flags().GetBool("init")

	logger.Info("Creating backup repository",
		zap.String("name", name),
		zap.String("backend", backend))

	// Build repository URL based on backend
	if backend == "local" {
		if path == "" {
			return fmt.Errorf("--path required for local backend")
		}
		url = path
	} else if url == "" {
		return fmt.Errorf("--url required for %s backend", backend)
	}

	// Parse environment variables
	envMap := make(map[string]string)
	for _, env := range envVars {
		var key, value string
		if _, err := fmt.Sscanf(env, "%s=%s", &key, &value); err != nil {
			return fmt.Errorf("invalid environment variable format: %s", env)
		}
		envMap[key] = value
	}

	// Load existing config
	config, err := LoadConfig(rc)
	if err != nil {
		logger.Warn("Failed to load existing config, creating new",
			zap.Error(err))
		config = &Config{
			Repositories: make(map[string]Repository),
			Profiles:     make(map[string]Profile),
		}
	}

	// Check if repository already exists
	if _, exists := config.Repositories[name]; exists {
		return fmt.Errorf("repository %q already exists", name)
	}

	// Create repository configuration
	repo := Repository{
		Name:        name,
		Backend:     backend,
		URL:         url,
		Environment: envMap,
	}

	// Generate secure password and store in Vault
	logger.Info("Generating repository password")
	password, err := generateSecurePassword()
	if err != nil {
		return fmt.Errorf("generating password: %w", err)
	}

	// Store password in Vault
	vaultPath := fmt.Sprintf("%s/%s", VaultPasswordPathPrefix, name)
	logger.Info("Storing repository password in Vault",
		zap.String("path", vaultPath))

	vaultAddr := shared.GetVaultAddrWithEnv()

	// Try to connect to Vault
	_, err = vault.NewClient(vaultAddr, logger.Logger().Logger)
	if err != nil {
		// Fall back to local storage
		logger.Warn("Vault unavailable, storing password locally",
			zap.Error(err))

		if err := storeLocalPassword(name, password); err != nil {
			return fmt.Errorf("storing password locally: %w", err)
		}
	} else {
		secretData := map[string]interface{}{
			VaultPasswordKey: password,
			"backend":        backend,
			"url":            url,
		}

		err = vault.WriteToVault(rc, vaultPath, secretData)
		if err != nil {
			return fmt.Errorf("storing password in vault: %w", err)
		}
	}

	// Add repository to config
	config.Repositories[name] = repo

	// Set as default if it's the first repository
	if len(config.Repositories) == 1 {
		config.DefaultRepository = name
	}

	// Save configuration
	if err := SaveConfig(rc, config); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	logger.Info("Repository created successfully",
		zap.String("name", name),
		zap.String("backend", backend))

	// Initialize repository if requested
	if doInit {
		logger.Info("Initializing repository")

		client, err := NewClient(rc, name)
		if err != nil {
			return fmt.Errorf("creating backup client: %w", err)
		}

		if err := client.InitRepository(); err != nil {
			return fmt.Errorf("initializing repository: %w", err)
		}

		logger.Info("Repository initialized successfully")
	}

	return nil
}

func CreateProfile(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	name := args[0]
	repoName, _ := cmd.Flags().GetString("repo")
	paths, _ := cmd.Flags().GetStringSlice("paths")
	excludes, _ := cmd.Flags().GetStringSlice("exclude")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	host, _ := cmd.Flags().GetString("host")
	description, _ := cmd.Flags().GetString("description")
	schedule, _ := cmd.Flags().GetString("schedule")

	logger.Info("Creating backup profile",
		zap.String("name", name),
		zap.String("repository", repoName),
		zap.Strings("paths", paths))

	// Load existing config
	config, err := LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// Verify repository exists
	if _, exists := config.Repositories[repoName]; !exists {
		return fmt.Errorf("repository %q not found", repoName)
	}

	// Check if profile already exists
	if _, exists := config.Profiles[name]; exists {
		return fmt.Errorf("profile %q already exists", name)
	}

	// Build profile
	profile := Profile{
		Name:        name,
		Description: description,
		Repository:  repoName,
		Paths:       paths,
		Excludes:    excludes,
		Tags:        tags,
		Host:        host,
	}

	// Add retention policy if specified
	retentionLast, _ := cmd.Flags().GetInt("retention-last")
	retentionDaily, _ := cmd.Flags().GetInt("retention-daily")
	retentionWeekly, _ := cmd.Flags().GetInt("retention-weekly")
	retentionMonthly, _ := cmd.Flags().GetInt("retention-monthly")
	retentionYearly, _ := cmd.Flags().GetInt("retention-yearly")

	if retentionLast > 0 || retentionDaily > 0 || retentionWeekly > 0 ||
		retentionMonthly > 0 || retentionYearly > 0 {
		profile.Retention = &Retention{
			KeepLast:    retentionLast,
			KeepDaily:   retentionDaily,
			KeepWeekly:  retentionWeekly,
			KeepMonthly: retentionMonthly,
			KeepYearly:  retentionYearly,
		}
	}

	// Add schedule if specified
	if schedule != "" {
		profile.Schedule = &Schedule{
			Cron: schedule,
		}
	}

	// Add profile to config
	config.Profiles[name] = profile

	// Save configuration
	if err := SaveConfig(rc, config); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	logger.Info("Profile created successfully",
		zap.String("name", name),
		zap.Int("paths", len(paths)),
		zap.Int("excludes", len(excludes)))

	// Create systemd timer if schedule specified
	if schedule != "" {
		logger.Info("Creating systemd timer for scheduled backups",
			zap.String("schedule", schedule))
		// TODO: Implement systemd timer creation
	}

	return nil
}

// generateSecurePassword generates a cryptographically secure random password
// SECURITY: Uses crypto/rand to ensure unpredictable passwords for backup encryption
func generateSecurePassword() (string, error) {
	const (
		length  = 32
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
	)

	// Generate random bytes
	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random password: %w", err)
	}

	// Map random bytes to charset to ensure printable characters
	password := make([]byte, length)
	for i, b := range randomBytes {
		password[i] = charset[int(b)%len(charset)]
	}

	return string(password), nil
}

func storeLocalPassword(repoName, password string) error {
	repoName = strings.TrimSpace(repoName)
	if repoName == "" {
		return fmt.Errorf("repository name is required")
	}
	if strings.Contains(repoName, "/") || strings.Contains(repoName, "..") {
		return fmt.Errorf("invalid repository name %q", repoName)
	}

	if err := ensureSecretsDirSecure(secretsDirPath); err != nil {
		return err
	}

	passwordPath := filepath.Join(filepath.Clean(secretsDirPath), fmt.Sprintf("%s.password", repoName))
	if err := secureWriteSecretFile(passwordPath, []byte(password), PasswordFilePerm); err != nil {
		return fmt.Errorf("writing password file securely: %w", err)
	}

	return nil
}

func ensureSecretsDirSecure(path string) error {
	cleanPath := filepath.Clean(path)
	if err := os.MkdirAll(cleanPath, PasswordDirPerm); err != nil {
		return fmt.Errorf("creating secrets directory: %w", err)
	}

	info, err := os.Lstat(cleanPath)
	if err != nil {
		return fmt.Errorf("stating secrets directory: %w", err)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("secrets directory %s must not be a symlink", cleanPath)
	}

	if !info.IsDir() {
		return fmt.Errorf("secrets path is not a directory: %s", cleanPath)
	}

	dirFD, err := openVerifiedSecretsDir(cleanPath)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)

	// SECURITY: Use FD-based Fchmod only (race-free).
	// Path-based os.Chmod is TOCTOU-vulnerable and redundant here.
	if info.Mode().Perm() != PasswordDirPerm {
		if err := unix.Fchmod(dirFD, uint32(PasswordDirPerm)); err != nil {
			return fmt.Errorf("enforcing secrets directory permissions: %w", err)
		}
	}

	return nil
}

func openVerifiedSecretsDir(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("opening secrets directory %s securely: %w", path, err)
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("stating secrets directory %s: %w", path, err)
	}

	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(fd)
		return -1, fmt.Errorf("secrets path is not a directory: %s", path)
	}
	if int(stat.Uid) != os.Geteuid() {
		unix.Close(fd)
		return -1, fmt.Errorf("secrets directory %s must be owned by uid %d (found %d)", path, os.Geteuid(), stat.Uid)
	}

	return fd, nil
}

func secureWriteSecretFile(path string, data []byte, perm os.FileMode) error {
	cleanPath := filepath.Clean(path)
	parentDir := filepath.Dir(cleanPath)
	fileName := filepath.Base(cleanPath)
	if fileName == "." || fileName == string(filepath.Separator) {
		return fmt.Errorf("invalid secret file path: %s", cleanPath)
	}

	dirFD, err := openVerifiedSecretsDir(parentDir)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)

	// SECURITY: Atomic write pattern (write-to-temp then renameat).
	// O_CREAT|O_EXCL ensures the temp file is freshly created (no clobber).
	// On crash, only the temp file is damaged; the original remains intact.
	// Reference: CWE-367, POSIX rename(2) atomicity guarantee.
	tmpName := fmt.Sprintf(".%s.tmp.%d", fileName, os.Getpid())

	tmpFD, err := unix.Openat(dirFD, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(perm))
	if err != nil {
		return fmt.Errorf("creating temp file for %s: %w", cleanPath, err)
	}

	// Clean up the temp file on any error path.
	committed := false
	defer func() {
		if !committed {
			_ = unix.Unlinkat(dirFD, tmpName, 0)
		}
	}()

	tmpFile := os.NewFile(uintptr(tmpFD), filepath.Join(parentDir, tmpName))
	defer tmpFile.Close()

	written, err := tmpFile.Write(data)
	if err != nil {
		return fmt.Errorf("writing %s: %w", cleanPath, err)
	}
	if written != len(data) {
		return fmt.Errorf("short write to %s: wrote %d of %d bytes", cleanPath, written, len(data))
	}

	if err := unix.Fchmod(tmpFD, uint32(perm)); err != nil {
		return fmt.Errorf("setting permissions on %s: %w", cleanPath, err)
	}

	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("syncing %s: %w", cleanPath, err)
	}

	// SECURITY: Before atomic rename, verify the target is not a symlink.
	// An attacker could place a symlink at the target path; renameat would
	// replace it, but we want to reject the write entirely to avoid confusion.
	var targetStat unix.Stat_t
	err = unix.Fstatat(dirFD, fileName, &targetStat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil && targetStat.Mode&unix.S_IFMT == unix.S_IFLNK {
		return fmt.Errorf("refusing to overwrite symlink at %s", cleanPath)
	}

	// Atomic rename: replaces target only after data is fully written and synced.
	if err := unix.Renameat(dirFD, tmpName, dirFD, fileName); err != nil {
		return fmt.Errorf("atomically replacing %s: %w", cleanPath, err)
	}
	committed = true

	return nil
}
