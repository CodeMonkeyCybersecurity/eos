package repository

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/joho/godotenv"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

const (
	// EnvFilePath is the canonical location for EOS secrets prior to Vault migration.
	EnvFilePath = "/etc/eos/secrets.env"

	// DefaultGiteaURL is aligned with `eos deploy gitea` defaults.
	DefaultGiteaURL = "http://vhost7:8167"
	// DefaultGiteaUser reflects the default admin user provisioned by EOS.
	DefaultGiteaUser = "henry"
)

// CredentialOptions control how credential discovery is performed.
type CredentialOptions struct {
	Interactive bool
	UseVault    bool
}

// GetGiteaConfig resolves the configuration for talking to Gitea.
func GetGiteaConfig(rc *eos_io.RuntimeContext, opts CredentialOptions) (*GiteaConfig, error) {
	if opts.UseVault {
		return getGiteaConfigFromVault(rc)
	}
	return loadGiteaConfigFromEnv(rc, opts.Interactive)
}

// loadGiteaConfigFromEnv loads credentials from the legacy .env store.
func loadGiteaConfigFromEnv(rc *eos_io.RuntimeContext, interactive bool) (*GiteaConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	values, err := godotenv.Read(EnvFilePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to read %s: %w", EnvFilePath, err)
	}

	cfg := &GiteaConfig{
		URL:      strings.TrimSpace(values["GITEA_URL"]),
		Token:    strings.TrimSpace(values["GITEA_TOKEN"]),
		Username: strings.TrimSpace(values["GITEA_USER"]),
	}

	if cfg.URL == "" {
		cfg.URL = DefaultGiteaURL
	}
	if cfg.Username == "" {
		cfg.Username = DefaultGiteaUser
	}

	// If token missing and interactive allowed, run setup wizard.
	if cfg.Token == "" && interactive {
		return setupGiteaInteractive(rc, cfg)
	}

	// Non-interactive mode must fail fast if information is incomplete.
	if cfg.Token == "" {
		return nil, fmt.Errorf("GITEA_TOKEN missing in %s; re-run without --non-interactive to configure", EnvFilePath)
	}

	if cfg.URL == "" || cfg.Username == "" {
		var fields []zap.Field
		if cfg.URL != "" {
			fields = append(fields, zap.String("url", cfg.URL))
		}
		if cfg.Username != "" {
			fields = append(fields, zap.String("username", cfg.Username))
		}
		logger.Warn("Partial Gitea configuration detected; using defaults where applicable", fields...)
	}

	return cfg, nil
}

// setupGiteaInteractive prompts the operator for required configuration.
func setupGiteaInteractive(rc *eos_io.RuntimeContext, defaults *GiteaConfig) (*GiteaConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Printf("\n⚠️  Gitea credentials not found in %s\n", EnvFilePath)
	fmt.Println("Let's set up your Gitea connection:")

	reader := bufio.NewReader(os.Stdin)

	url := promptWithDefault(reader, "Gitea URL", defaultIfEmpty(defaults.URL, DefaultGiteaURL))
	username := promptWithDefault(reader, "Username", defaultIfEmpty(defaults.Username, DefaultGiteaUser))

	fmt.Println("To generate an API token:")
	fmt.Printf("  1. Visit %s/user/settings/applications\n", url)
	fmt.Println("  2. Click 'Generate New Token'")
	fmt.Println("  3. Give it a name (e.g., 'EOS CLI')")
	fmt.Println("  4. Select 'repo' scope")
	fmt.Println("  5. Copy the generated token")

	token := promptSecret("API Token")
	if token == "" {
		return nil, errors.New("API token is required")
	}

	cfg := &GiteaConfig{
		URL:      url,
		Token:    token,
		Username: username,
	}

	if err := saveGiteaConfig(cfg); err != nil {
		return nil, fmt.Errorf("failed to persist Gitea credentials: %w", err)
	}

	fields := []zap.Field{zap.String("store", EnvFilePath)}
	if cfg.URL != "" {
		fields = append(fields, zap.String("url", cfg.URL))
	}
	logger.Info("Gitea credentials saved for eos create repo workflow", fields...)

	fmt.Printf("\n✓ Credentials saved to %s\n", EnvFilePath)
	fmt.Println("✓ File permissions set to 600")
	fmt.Println("Continuing with repository creation...")

	return cfg, nil
}

// saveGiteaConfig merges Gitea credentials into the shared secrets file.
func saveGiteaConfig(cfg *GiteaConfig) error {
	if cfg == nil {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(EnvFilePath), 0o755); err != nil {
		return err
	}

	values, err := godotenv.Read(EnvFilePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if values == nil {
		values = make(map[string]string)
	}

	values["GITEA_URL"] = cfg.URL
	values["GITEA_TOKEN"] = cfg.Token
	values["GITEA_USER"] = cfg.Username

	file, err := os.OpenFile(EnvFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	writer := bufio.NewWriter(file)
	for _, key := range keys {
		value := escapeEnvValue(values[key])
		if _, err := fmt.Fprintf(writer, "%s=\"%s\"\n", key, value); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}

	return os.Chmod(EnvFilePath, 0o600)
}

// promptWithDefault reads a line of input and falls back to a default value if empty.
func promptWithDefault(reader *bufio.Reader, label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", label, defaultVal)
	} else {
		fmt.Printf("%s: ", label)
	}
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	if text == "" {
		return defaultVal
	}
	return text
}

// promptSecret reads a value from stdin without echoing.
func promptSecret(label string) string {
	fmt.Printf("%s: ", label)
	bytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(bytes))
}

func defaultIfEmpty(val, fallback string) string {
	if strings.TrimSpace(val) == "" {
		return fallback
	}
	return val
}

func escapeEnvValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}

func getGiteaConfigFromVault(rc *eos_io.RuntimeContext) (*GiteaConfig, error) {
	otelzap.Ctx(rc.Ctx).Warn("Vault-backed Gitea credential retrieval is not implemented yet")
	return nil, errors.New("vault support for Gitea credentials will be available after July 1, 2026")
}
