// cmd/debug/moni.go
// Moni/BionicGPT authentication + LiteLLM debugging

package debug

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var debugMoniCmd = &cobra.Command{
	Use:   "moni",
	Short: "Debug Moni/BionicGPT authentication and LiteLLM integration",
	Long: `Diagnose why Moni/BionicGPT isn't sending API keys to LiteLLM.

This runs a series of checks analogous to the shell script you provided:
- Detect install dir (/opt/moni or /opt/bionicgpt)
- Inspect .env for OPENAI_API_KEY and LITELLM_MASTER_KEY
- Check docker compose environment for OPENAI_API_KEY in app container
- Test LiteLLM auth against http://localhost:4000/v1/models
- Query database models table for api_key presence
- Scan docker-compose.yml for env settings

Output is printed in a human-friendly format with recommendations.`,
	RunE: eos_cli.WrapDebug("moni", runDebugMoni),
}

func init() {
	debugCmd.AddCommand(debugMoniCmd)
}

func runDebugMoni(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("==================================================")
	fmt.Println("BionicGPT Authentication Debugging")
	fmt.Println("==================================================")
	fmt.Println("")

	installDir, err := detectMoniDir()
	if err != nil {
		fmt.Println("❌ ERROR: Cannot find BionicGPT directory")
		fmt.Println("   Checked: /opt/moni, /opt/bionicgpt")
		return err
	}
	fmt.Printf("✓ Working directory: %s\n\n", installDir)

	// STEP 1: .env
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("STEP 1: Checking .env file configuration")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	envPath := filepath.Join(installDir, ".env")
	envVars, envExists, envErr := readDotEnv(envPath)
	if !envExists || envErr != nil {
		fmt.Println("❌ .env file not found!")
		if envErr != nil {
			logger.Warn(".env read error", zap.Error(envErr))
		}
		return errors.New(".env not found")
	}

	checkKey("OPENAI_API_KEY", envVars)
	fmt.Println("")
	checkKey("LITELLM_MASTER_KEY", envVars)
	fmt.Println("")

	// STEP 2: docker-compose env
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("STEP 2: Checking docker-compose environment")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	appService, err := detectComposeService(rc, installDir, []string{"app", "bionicgpt-app"})
	if err != nil {
		fmt.Println("❌ app container not found (looked for: app, bionicgpt-app)")
		fmt.Println("   Try: docker compose ps")
	} else {
		fmt.Println("Checking environment variables in app container...")
		out, err := execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args:    []string{"compose", "exec", "-T", appService, "env"},
			Dir:     installDir,
			Capture: true,
			Timeout: 10 * time.Second,
		})
		if err != nil {
			logger.Warn("failed to exec env in app container", zap.Error(err))
			fmt.Println("❌ Could not read environment from app container")
		} else {
			if hasEnvLine(out, "OPENAI_API_KEY") {
				val := extractEnvValue(out, "OPENAI_API_KEY")
				if strings.TrimSpace(val) == "" {
					fmt.Println("❌ OPENAI_API_KEY in container is EMPTY")
				} else {
					fmt.Println("✓ OPENAI_API_KEY is loaded in app container")
				}
			} else {
				fmt.Println("❌ OPENAI_API_KEY NOT found in app container environment")
			}
		}
	}

	fmt.Println("")

	// STEP 3: Test LiteLLM authentication
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("STEP 3: Testing LiteLLM authentication")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	liteKey := envVars["LITELLM_MASTER_KEY"]
	if liteKey != "" {
		fmt.Println("Testing with master key from .env...")
		status, body := httpGetWithAuth("http://localhost:4000/v1/models", liteKey)
		switch status {
		case 200:
			fmt.Println("✓ LiteLLM authentication works with master key")
			// Try parse model list
			var parsed struct {
				Data []struct {
					ID string `json:"id"`
				}
			}
			if err := json.Unmarshal([]byte(body), &parsed); err == nil && len(parsed.Data) > 0 {
				fmt.Println("  Available models:")
				for _, m := range parsed.Data {
					if m.ID != "" {
						fmt.Printf("    - %s\n", m.ID)
					}
				}
			}
		case 401:
			fmt.Println("❌ LiteLLM returned 401 Unauthorized")
			fmt.Println("   Response:")
			fmt.Println(indentJSONIfPossible(body))
		default:
			fmt.Printf("❌ LiteLLM returned HTTP %d\n", status)
		}
	} else {
		fmt.Println("⚠️  No LITELLM_MASTER_KEY found to test with")
	}

	fmt.Println("")

	// STEP 4: DB models table
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("STEP 4: Checking BionicGPT database model configuration")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	dbService, dbErr := detectComposeService(rc, installDir, []string{"db", "bionicgpt-db"})
	if dbErr != nil {
		fmt.Println("⚠️  Cannot access database container")
	} else {
		fmt.Println("Querying models table...")
		queryOut, err := execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args:    []string{"compose", "exec", "-T", dbService, "psql", "-U", "postgres", "-d", "bionic-gpt", "-t", "-c", "SELECT id, name, base_url, api_key FROM models;"},
			Dir:     installDir,
			Capture: true,
			Timeout: 10 * time.Second,
		})
		if err != nil || strings.TrimSpace(queryOut) == "" {
			fmt.Println("⚠️  No models found in database or cannot query")
			if err != nil {
				logger.Warn("psql query failed", zap.Error(err))
			}
		} else {
			// Parse rows separated by newlines with '|' delimiters
			scanner := bufio.NewScanner(strings.NewReader(queryOut))
			printed := false
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				parts := strings.Split(line, "|")
				if len(parts) < 4 {
					continue
				}
				id := strings.TrimSpace(parts[0])
				if id == "" {
					continue
				}
				name := strings.TrimSpace(parts[1])
				baseURL := strings.TrimSpace(parts[2])
				apiKey := strings.TrimSpace(parts[3])
				if !printed {
					fmt.Println("✓ Found models in database:")
					printed = true
				}
				fmt.Printf("  Model ID: %s\n", id)
				fmt.Printf("    Name: %s\n", name)
				fmt.Printf("    Base URL: %s\n", baseURL)
				if apiKey == "" {
					fmt.Println("    ❌ API Key: NOT SET")
				} else {
					fmt.Printf("    ✓ API Key: SET (length: %d)\n", len(apiKey))
				}
				fmt.Println("")
			}
			if !printed {
				fmt.Println("⚠️  No models found in database or cannot query")
			}
		}
	}

	fmt.Println("")

	// STEP 5: docker-compose.yml scan
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("STEP 5: Checking docker-compose.yml")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	composePath := filepath.Join(installDir, "docker-compose.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		fmt.Println("❌ docker-compose.yml not found")
	} else {
		// Heuristic scan for app service block
		fmt.Println("Checking app service environment...")
		txt := string(data)
		block := findServiceBlock(txt, []string{"bionicgpt-app", "app"}, 40)
		if block == "" {
			fmt.Println("⚠️  Could not find app service block in docker-compose.yml")
		} else {
			if strings.Contains(block, "OPENAI_API_KEY") {
				fmt.Println("✓ OPENAI_API_KEY referenced in docker-compose.yml")
			} else {
				fmt.Println("❌ OPENAI_API_KEY NOT found in docker-compose.yml app service")
			}
			if strings.Contains(block, "env_file:") {
				fmt.Println("✓ env_file directive present in app service")
			} else {
				fmt.Println("⚠️  No env_file directive in app service")
			}
		}
	}

	fmt.Println("")

	// SUMMARY
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("SUMMARY")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("")
	fmt.Println("Common issues and fixes:")
	fmt.Println("")
	fmt.Println("1. If OPENAI_API_KEY is commented out in .env:")
	fmt.Println("   → Uncomment it or set it to your LITELLM_MASTER_KEY")
	fmt.Println("")
	fmt.Println("2. If OPENAI_API_KEY is not in app container:")
	fmt.Println("   → Add 'env_file: - .env' to app service in docker-compose.yml")
	fmt.Println("   → Or add OPENAI_API_KEY explicitly in environment section")
	fmt.Println("")
	fmt.Println("3. If models in database have no API key:")
	fmt.Println("   → Run: docker compose exec -T db psql -U postgres -d bionic-gpt -c \\")
	fmt.Println("     \"UPDATE models SET api_key = '${LITELLM_MASTER_KEY}' WHERE api_key IS NULL;\"")
	fmt.Println("")
	fmt.Println("4. If LiteLLM authentication fails:")
	fmt.Println("   → Ensure LITELLM_MASTER_KEY starts with 'sk-'")
	fmt.Println("   → Regenerate with: echo \"sk-$(openssl rand -base64 32 | tr -d '/+=')\"")
	fmt.Println("")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	logger.Info("moni/bionicgpt debug completed", zap.String("install_dir", installDir))
	return nil
}

func detectMoniDir() (string, error) {
	candidates := []string{"/opt/moni", "/opt/bionicgpt"}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("moni/bionicgpt install dir not found")
}

// readDotEnv reads KEY=VALUE pairs from a .env file without strict parsing.
func readDotEnv(path string) (map[string]string, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	vars := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			// Keep track of commented keys for messaging via presence check below
			continue
		}
		if !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, "'\"")
		vars[key] = val
	}
	return vars, true, nil
}

func checkKey(name string, vars map[string]string) {
	fmt.Printf("Checking for %s...\n", name)
	val, ok := vars[name]
	if !ok {
		fmt.Printf("❌ %s not found in .env\n", name)
		return
	}
	if strings.TrimSpace(val) == "" {
		fmt.Printf("❌ %s is set but EMPTY\n", name)
		return
	}
	fmt.Printf("✓ %s is set in .env\n", name)
	if strings.HasPrefix(val, "sk-") {
		fmt.Println("  ✓ Key has correct sk- prefix")
	} else {
		fmt.Println("  ⚠️  Key does NOT have sk- prefix (may cause issues)")
	}
}

func detectComposeService(rc *eos_io.RuntimeContext, dir string, preferred []string) (string, error) {
	out, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "ps", "--services"},
		Dir:     dir,
		Capture: true,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return "", err
	}
	services := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		s := strings.TrimSpace(scanner.Text())
		if s != "" {
			services[s] = true
		}
	}
	for _, name := range preferred {
		if services[name] {
			return name, nil
		}
	}
	// fallback: pick any service that matches contains of preferred tokens
	for s := range services {
		for _, p := range preferred {
			if strings.Contains(s, p) {
				return s, nil
			}
		}
	}
	return "", errors.New("service not found")
}

func hasEnvLine(allEnv string, key string) bool {
	re := regexp.MustCompile("(?m)^" + regexp.QuoteMeta(key) + "=")
	return re.FindStringIndex(allEnv) != nil
}

func extractEnvValue(allEnv, key string) string {
	scanner := bufio.NewScanner(strings.NewReader(allEnv))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimPrefix(line, key+"=")
		}
	}
	return ""
}

func httpGetWithAuth(url, token string) (int, string) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func indentJSONIfPossible(s string) string {
	var js map[string]interface{}
	if err := json.Unmarshal([]byte(s), &js); err == nil {
		pretty, _ := json.MarshalIndent(js, "", "  ")
		return string(pretty)
	}
	return s
}

func findServiceBlock(yaml string, candidates []string, contextLines int) string {
	lines := strings.Split(yaml, "\n")
	for i, line := range lines {
		for _, c := range candidates {
			if strings.HasPrefix(strings.TrimSpace(line), c+":") {
				// capture next N lines
				end := i + 1 + contextLines
				if end > len(lines) {
					end = len(lines)
				}
				return strings.Join(lines[i:end], "\n")
			}
		}
	}
	return ""
}
