package langfuse

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	containerexec "github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	defaultLangfuseContainer = "bionicgpt-langfuse"
	defaultDatabaseContainer = "bionicgpt-langfuse-db"
	defaultDatabaseUser      = "langfuse"
	defaultDatabaseName      = "langfuse"
	defaultLangfuseURL       = "http://localhost:3000"
)

// Config provides inputs for Langfuse diagnostics.
type Config struct {
	LangfuseContainer string
	DatabaseContainer string
	LangfuseURL       string
	DatabaseUser      string
	DatabaseName      string
	LogTailLines      int
	SkipHTTPCheck     bool
}

// DiagnosticsResult aggregates the outcome of each diagnostic step.
type DiagnosticsResult struct {
	Checks        []string
	Warnings      []string
	Errors        []string
	EnvFindings   map[string]string
	LogTail       string
	DatabaseUsers string
	HTTPStatus    string
}

// RunDiagnostics executes a sequence of diagnostics against a Langfuse deployment.
func RunDiagnostics(rc *eos_io.RuntimeContext, cfg *Config) error {
	cfg = normalizeConfig(cfg)

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Langfuse diagnostics",
		zap.String("langfuse_container", cfg.LangfuseContainer),
		zap.String("database_container", cfg.DatabaseContainer),
		zap.String("langfuse_url", cfg.LangfuseURL),
		zap.Int("log_tail_lines", cfg.LogTailLines),
		zap.Bool("skip_http_check", cfg.SkipHTTPCheck),
	)

	result := &DiagnosticsResult{
		EnvFindings: make(map[string]string),
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("creating docker client: %w", err)
	}
	defer func() {
		if cerr := cli.Close(); cerr != nil {
			logger.Warn("Failed to close docker client", zap.Error(cerr))
		}
	}()

	if err := inspectLangfuseContainer(rc, cli, cfg, result); err != nil {
		result.Errors = append(result.Errors, err.Error())
		logger.Warn("Langfuse container inspection failed", zap.Error(err))
	}

	if err := inspectDatabaseContainer(rc, cli, cfg, result); err != nil {
		result.Errors = append(result.Errors, err.Error())
		logger.Warn("Database container inspection failed", zap.Error(err))
	}

	if result.LogTail == "" {
		if err := collectLangfuseLogs(rc, cli, cfg, result); err != nil {
			logger.Warn("Failed to collect Langfuse logs", zap.Error(err))
			result.Warnings = append(result.Warnings, fmt.Sprintf("Langfuse log collection failed: %v", err))
		}
	}

	if result.DatabaseUsers == "" {
		if err := collectDatabaseUsers(rc, cfg, result); err != nil {
			logger.Warn("Failed to query Langfuse database", zap.Error(err))
			result.Warnings = append(result.Warnings, fmt.Sprintf("Database query failed: %v", err))
		}
	}

	if !cfg.SkipHTTPCheck {
		if err := checkHTTPReachability(rc, cfg, result); err != nil {
			logger.Warn("HTTP reachability check failed", zap.Error(err))
			result.Warnings = append(result.Warnings, fmt.Sprintf("HTTP reachability failed: %v", err))
		}
	}

	displayLangfuseResults(result)

	if len(result.Errors) > 0 {
		return fmt.Errorf("langfuse diagnostics detected %d error(s)", len(result.Errors))
	}
	return nil
}

func normalizeConfig(cfg *Config) *Config {
	if cfg == nil {
		cfg = &Config{}
	}

	if cfg.LangfuseContainer == "" {
		cfg.LangfuseContainer = defaultLangfuseContainer
	}
	if cfg.DatabaseContainer == "" {
		cfg.DatabaseContainer = defaultDatabaseContainer
	}
	if cfg.DatabaseUser == "" {
		cfg.DatabaseUser = defaultDatabaseUser
	}
	if cfg.DatabaseName == "" {
		cfg.DatabaseName = defaultDatabaseName
	}
	if cfg.LangfuseURL == "" {
		cfg.LangfuseURL = defaultLangfuseURL
	}
	if cfg.LogTailLines <= 0 {
		cfg.LogTailLines = 200
	}
	return cfg
}

func inspectLangfuseContainer(rc *eos_io.RuntimeContext, cli *client.Client, cfg *Config, result *DiagnosticsResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	info, err := cli.ContainerInspect(rc.Ctx, cfg.LangfuseContainer)
	if err != nil {
		if client.IsErrNotFound(err) {
			return fmt.Errorf("langfuse container %q not found", cfg.LangfuseContainer)
		}
		return fmt.Errorf("inspect langfuse container %q: %w", cfg.LangfuseContainer, err)
	}

	if info.State != nil && info.State.Running {
		result.Checks = append(result.Checks, fmt.Sprintf("Langfuse container %s is running", cfg.LangfuseContainer))
	} else {
		result.Errors = append(result.Errors, fmt.Sprintf("Langfuse container %s is not running", cfg.LangfuseContainer))
	}

	envMap := envSliceToMap(info.Config.Env)
	required := []string{"NEXTAUTH_SECRET", "NEXTAUTH_URL", "SALT", "DATABASE_URL"}
	for _, key := range required {
		if value, ok := envMap[key]; ok && value != "" {
			result.EnvFindings[key] = redactEnvValue(key, value)
		} else {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Langfuse container missing required env: %s", key))
		}
	}

	// Capture port bindings for operator visibility.
	if info.NetworkSettings != nil && len(info.NetworkSettings.Ports) > 0 {
		var published []string
		for port, bindings := range info.NetworkSettings.Ports {
			if len(bindings) == 0 {
				continue
			}
			for _, binding := range bindings {
				published = append(published, fmt.Sprintf("%s->%s:%s", port.Port(), binding.HostIP, binding.HostPort))
			}
		}
		if len(published) > 0 {
			sort.Strings(published)
			result.Checks = append(result.Checks, fmt.Sprintf("Langfuse published ports: %s", strings.Join(published, ", ")))
		}
	}

	logger.Info("Langfuse container inspected",
		zap.Bool("running", info.State != nil && info.State.Running),
		zap.Int("env_vars", len(info.Config.Env)),
	)

	return nil
}

func inspectDatabaseContainer(rc *eos_io.RuntimeContext, cli *client.Client, cfg *Config, result *DiagnosticsResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	info, err := cli.ContainerInspect(rc.Ctx, cfg.DatabaseContainer)
	if err != nil {
		if client.IsErrNotFound(err) {
			return fmt.Errorf("database container %q not found", cfg.DatabaseContainer)
		}
		return fmt.Errorf("inspect database container %q: %w", cfg.DatabaseContainer, err)
	}

	if info.State != nil && info.State.Running {
		result.Checks = append(result.Checks, fmt.Sprintf("Database container %s is running", cfg.DatabaseContainer))
	} else {
		result.Errors = append(result.Errors, fmt.Sprintf("Database container %s is not running", cfg.DatabaseContainer))
	}

	logger.Info("Database container inspected",
		zap.Bool("running", info.State != nil && info.State.Running),
	)

	return nil
}

func collectLangfuseLogs(rc *eos_io.RuntimeContext, cli *client.Client, cfg *Config, result *DiagnosticsResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	options := dockertypes.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       fmt.Sprintf("%d", cfg.LogTailLines),
	}

	reader, err := cli.ContainerLogs(rc.Ctx, cfg.LangfuseContainer, options)
	if err != nil {
		return fmt.Errorf("fetch langfuse logs: %w", err)
	}
	defer func() {
		if cerr := reader.Close(); cerr != nil {
			logger.Warn("Failed to close log reader", zap.Error(cerr))
		}
	}()

	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("read langfuse log stream: %w", err)
	}

	logText := string(data)
	result.LogTail = logText

	for _, finding := range detectLogFindings(logText) {
		result.Warnings = append(result.Warnings, finding)
	}

	logger.Info("Collected Langfuse logs",
		zap.Int("bytes", len(data)),
		zap.Int("log_tail_lines", cfg.LogTailLines),
	)

	return nil
}

func collectDatabaseUsers(rc *eos_io.RuntimeContext, cfg *Config, result *DiagnosticsResult) error {
	cmd := []string{
		"psql",
		"-U", cfg.DatabaseUser,
		"-d", cfg.DatabaseName,
		"-c", "SELECT email, name, created_at FROM users ORDER BY created_at DESC LIMIT 5;",
	}

	output, err := containerexec.ExecCommandInContainer(rc, containerexec.ExecConfig{
		ContainerName: cfg.DatabaseContainer,
		Cmd:           cmd,
	})
	if err != nil {
		if output != "" {
			result.DatabaseUsers = output
		}
		return fmt.Errorf("exec database query: %w", err)
	}

	result.DatabaseUsers = output
	return nil
}

func checkHTTPReachability(rc *eos_io.RuntimeContext, cfg *Config, result *DiagnosticsResult) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	ctx := rc.Ctx
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(cfg.LangfuseURL, "/")+"/auth/sign-up", nil)
	if err != nil {
		return fmt.Errorf("build http request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("perform http request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	bodyPreview := make([]byte, 512)
	n, _ := resp.Body.Read(bodyPreview)

	result.HTTPStatus = fmt.Sprintf("%s %s (body preview: %s)", req.URL, resp.Status, sanitizePreview(string(bodyPreview[:n])))

	if resp.StatusCode >= 400 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Langfuse HTTP endpoint returned %s", resp.Status))
	} else {
		result.Checks = append(result.Checks, fmt.Sprintf("Langfuse HTTP endpoint reachable: %s", resp.Status))
	}

	return nil
}

func displayLangfuseResults(result *DiagnosticsResult) {
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("LANGFUSE DIAGNOSTICS SUMMARY")
	fmt.Println(strings.Repeat("=", 80))

	if len(result.Checks) > 0 {
		fmt.Println("\nChecks:")
		for _, check := range result.Checks {
			fmt.Printf("  • %s\n", check)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, warning := range result.Warnings {
			fmt.Printf("  • %s\n", warning)
		}
	}

	if len(result.Errors) > 0 {
		fmt.Println("\nErrors:")
		for _, err := range result.Errors {
			fmt.Printf("  • %s\n", err)
		}
	}

	if len(result.EnvFindings) > 0 {
		fmt.Println("\nEnvironment variables:")
		keys := make([]string, 0, len(result.EnvFindings))
		for key := range result.EnvFindings {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Printf("  %s=%s\n", key, result.EnvFindings[key])
		}
	}

	if result.HTTPStatus != "" {
		fmt.Println("\nHTTP Check:")
		fmt.Printf("  %s\n", result.HTTPStatus)
	}

	if result.DatabaseUsers != "" {
		fmt.Println("\nDatabase users (last 5 entries):")
		fmt.Println(indentBlock(strings.TrimSpace(result.DatabaseUsers)))
	}

	if result.LogTail != "" {
		fmt.Println("\nLangfuse logs (tail):")
		fmt.Println(indentBlock(strings.TrimSpace(result.LogTail)))
	}
}

func envSliceToMap(values []string) map[string]string {
	out := make(map[string]string, len(values))
	for _, env := range values {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		out[parts[0]] = parts[1]
	}
	return out
}

func redactEnvValue(key, value string) string {
	switch {
	case strings.Contains(strings.ToLower(key), "secret"),
		strings.Contains(strings.ToLower(key), "password"),
		strings.Contains(strings.ToLower(key), "token"):
		if len(value) <= 4 {
			return "****"
		}
		return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
	default:
		return value
	}
}

func detectLogFindings(logs string) []string {
	lower := strings.ToLower(logs)
	var findings []string

	if strings.Contains(lower, "error creating user") {
		findings = append(findings, "Detected 'Error creating user' in logs – confirm signup flow and database connectivity.")
	}
	if strings.Contains(lower, "next-auth") && strings.Contains(lower, "warning") {
		findings = append(findings, "NextAuth warnings present – verify NEXTAUTH_URL and NEXTAUTH_SECRET.")
	}
	if strings.Contains(lower, "econnrefused") {
		findings = append(findings, "Langfuse reported connection refused – database or upstream services may be unavailable.")
	}
	return findings
}

func indentBlock(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = "  " + line
	}
	return strings.Join(lines, "\n")
}

func sanitizePreview(body string) string {
	body = strings.TrimSpace(body)
	if len(body) > 120 {
		body = body[:117] + "..."
	}
	return strings.ReplaceAll(body, "\n", " ")
}
