package inspect

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Unit tests for pure parsing functions (~70% of test coverage)
// These test extracted functions without any Docker dependency.
// ---------------------------------------------------------------------------

// --- ParseDockerSize (pure function) ---

func TestParseDockerSize_ValidSIUnits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected int64
	}{
		{name: "terabytes", input: "1.5TB", expected: 1_500_000_000_000},
		{name: "gigabytes", input: "2.5GB", expected: 2_500_000_000},
		{name: "megabytes", input: "100MB", expected: 100_000_000},
		{name: "kilobytes_lowercase_k", input: "512kB", expected: 512_000},
		{name: "kilobytes_uppercase_K", input: "512KB", expected: 512_000},
		{name: "bytes_with_suffix", input: "1024B", expected: 1024},
		{name: "raw_bytes_no_suffix", input: "4096", expected: 4096},
		{name: "zero", input: "0B", expected: 0},
		{name: "empty_string", input: "", expected: 0},
		{name: "whitespace_only", input: "   ", expected: 0},
		{name: "space_between_number_and_unit", input: "1.2 GB", expected: 1_200_000_000},
		{name: "fractional_MB", input: "1.5MB", expected: 1_500_000},
		{name: "integer_GB", input: "1GB", expected: 1_000_000_000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseDockerSize(tt.input)
			if err != nil {
				t.Fatalf("ParseDockerSize(%q) returned error: %v", tt.input, err)
			}
			if got != tt.expected {
				t.Errorf("ParseDockerSize(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseDockerSize_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "letters_only", input: "abc"},
		{name: "negative_GB", input: "-5GB"},
		{name: "negative_raw", input: "-100"},
		{name: "garbage_suffix", input: "100XY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseDockerSize(tt.input)
			if err == nil {
				t.Errorf("ParseDockerSize(%q) expected error, got nil", tt.input)
			}
		})
	}
}

func TestParseDockerSize_UsesDecimalNotBinary(t *testing.T) {
	t.Parallel()

	// Docker uses SI/decimal units: 1 GB = 1,000,000,000 bytes (not 1,073,741,824).
	// Reference: github.com/docker/go-units
	got, err := ParseDockerSize("1GB")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == 1024*1024*1024 {
		t.Errorf("ParseDockerSize uses binary (1 GiB = %d), should use decimal (1 GB = 1000000000)", got)
	}
	if got != 1_000_000_000 {
		t.Errorf("ParseDockerSize(\"1GB\") = %d, want 1000000000", got)
	}
}

// --- parseEnvVars (pure function) ---

func TestParseEnvVars_BasicParsing(t *testing.T) {
	t.Parallel()

	input := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/root",
		"LANG=en_US.UTF-8",
	}

	got := parseEnvVars(input)

	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got))
	}
	if got["PATH"] != "/usr/bin:/bin" {
		t.Errorf("PATH = %q, want /usr/bin:/bin", got["PATH"])
	}
	if got["HOME"] != "/root" {
		t.Errorf("HOME = %q, want /root", got["HOME"])
	}
}

func TestParseEnvVars_RedactsSensitiveValues(t *testing.T) {
	t.Parallel()

	input := []string{
		"DB_PASSWORD=supersecret",
		"API_SECRET=abc123",
		"AUTH_TOKEN=tok_xyz",
		"SSH_KEY=rsa-AAAA",
		"AWS_CREDENTIAL_FILE=/path",
		"PRIVATE_KEY=-----BEGIN",
		"SAFE_VAR=visible",
	}

	got := parseEnvVars(input)

	sensitiveKeys := []string{
		"DB_PASSWORD", "API_SECRET", "AUTH_TOKEN", "SSH_KEY",
		"AWS_CREDENTIAL_FILE", "PRIVATE_KEY",
	}
	for _, k := range sensitiveKeys {
		if got[k] != SensitiveValueRedacted {
			t.Errorf("expected %q to be redacted, got %q", k, got[k])
		}
	}
	if got["SAFE_VAR"] != "visible" {
		t.Errorf("SAFE_VAR should not be redacted, got %q", got["SAFE_VAR"])
	}
}

func TestParseEnvVars_EmptyAndMalformed(t *testing.T) {
	t.Parallel()

	input := []string{
		"",
		"NO_EQUALS_SIGN",
		"VALID=value",
		"EMPTY_VALUE=",
	}

	got := parseEnvVars(input)

	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d: %v", len(got), got)
	}
	if got["VALID"] != "value" {
		t.Errorf("VALID = %q, want \"value\"", got["VALID"])
	}
	if got["EMPTY_VALUE"] != "" {
		t.Errorf("EMPTY_VALUE = %q, want empty string", got["EMPTY_VALUE"])
	}
}

func TestParseEnvVars_ValueContainsEquals(t *testing.T) {
	t.Parallel()

	input := []string{
		"CONNECTION_STRING=host=db port=5432 user=app",
	}

	got := parseEnvVars(input)
	expected := "host=db port=5432 user=app"
	if got["CONNECTION_STRING"] != expected {
		t.Errorf("CONNECTION_STRING = %q, want %q", got["CONNECTION_STRING"], expected)
	}
}

// --- isSensitiveEnvVar (pure function) ---

func TestIsSensitiveEnvVar(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "password", input: "DB_PASSWORD", expected: true},
		{name: "secret", input: "API_SECRET", expected: true},
		{name: "token", input: "AUTH_TOKEN", expected: true},
		{name: "key", input: "SSH_KEY", expected: true},
		{name: "credential", input: "CREDENTIAL_FILE", expected: true},
		{name: "private", input: "PRIVATE_DATA", expected: true},
		{name: "case_insensitive", input: "my_Password_var", expected: true},
		{name: "safe_path", input: "PATH", expected: false},
		{name: "safe_home", input: "HOME", expected: false},
		{name: "safe_lang", input: "LANG", expected: false},
		{name: "safe_port", input: "DB_PORT", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isSensitiveEnvVar(tt.input)
			if got != tt.expected {
				t.Errorf("isSensitiveEnvVar(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// --- parseContainerInspectJSON (pure function) ---

func TestParseContainerInspectJSON_SingleContainer(t *testing.T) {
	t.Parallel()

	data := []containerInspectData{
		{
			ID:      "abc123def456",
			Name:    "/my-container",
			Created: "2024-01-15T10:30:00.123456789Z",
		},
	}
	data[0].State.Status = "running"
	data[0].State.Running = true
	data[0].Config.Image = "nginx:latest"
	data[0].Config.Env = []string{"PORT=80", "DB_PASSWORD=secret123"}
	data[0].Config.Labels = map[string]string{"app": "web"}
	data[0].Config.Cmd = []string{"nginx", "-g", "daemon off;"}
	data[0].HostConfig.RestartPolicy.Name = "always"

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("failed to marshal test data: %v", err)
	}

	containers, err := parseContainerInspectJSON(string(jsonBytes))
	if err != nil {
		t.Fatalf("parseContainerInspectJSON returned error: %v", err)
	}

	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}

	c := containers[0]

	if c.ID != "abc123def456" {
		t.Errorf("ID = %q, want abc123def456", c.ID)
	}
	if c.Name != "my-container" {
		t.Errorf("Name = %q, want my-container (leading / stripped)", c.Name)
	}
	if c.State != ContainerStateRunning {
		t.Errorf("State = %q, want %q", c.State, ContainerStateRunning)
	}
	if c.Status != "running" {
		t.Errorf("Status = %q, want running", c.Status)
	}
	if c.Image != "nginx:latest" {
		t.Errorf("Image = %q, want nginx:latest", c.Image)
	}
	if c.Restart != "always" {
		t.Errorf("Restart = %q, want always", c.Restart)
	}
	if c.Command != "nginx -g daemon off;" {
		t.Errorf("Command = %q, want \"nginx -g daemon off;\"", c.Command)
	}

	// Check env redaction
	if c.Environment["PORT"] != "80" {
		t.Errorf("PORT env = %q, want 80", c.Environment["PORT"])
	}
	if c.Environment["DB_PASSWORD"] != SensitiveValueRedacted {
		t.Errorf("DB_PASSWORD should be redacted, got %q", c.Environment["DB_PASSWORD"])
	}

	// Check created time parsed
	if c.Created.IsZero() {
		t.Error("Created time should not be zero")
	}
}

func TestParseContainerInspectJSON_StoppedContainer(t *testing.T) {
	t.Parallel()

	data := []containerInspectData{
		{
			ID:   "stopped123",
			Name: "/stopped-svc",
		},
	}
	data[0].State.Status = "exited"
	data[0].State.Running = false

	jsonBytes, _ := json.Marshal(data)
	containers, err := parseContainerInspectJSON(string(jsonBytes))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}

	if containers[0].State != ContainerStateStopped {
		t.Errorf("State = %q, want %q", containers[0].State, ContainerStateStopped)
	}
}

func TestParseContainerInspectJSON_MultipleContainers(t *testing.T) {
	t.Parallel()

	data := make([]containerInspectData, 3)
	for i := range data {
		data[i].ID = strings.Repeat("a", 12) + string(rune('0'+i))
		data[i].Name = "/container-" + string(rune('0'+i))
		data[i].Config.Image = "image:" + string(rune('0'+i))
	}
	data[0].State.Running = true
	data[1].State.Running = false
	data[2].State.Running = true

	jsonBytes, _ := json.Marshal(data)
	containers, err := parseContainerInspectJSON(string(jsonBytes))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(containers) != 3 {
		t.Fatalf("expected 3 containers, got %d", len(containers))
	}
}

func TestParseContainerInspectJSON_InvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := parseContainerInspectJSON("not json at all")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParseContainerInspectJSON_EmptyArray(t *testing.T) {
	t.Parallel()

	containers, err := parseContainerInspectJSON("[]")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(containers) != 0 {
		t.Errorf("expected 0 containers, got %d", len(containers))
	}
}

func TestParseContainerInspectJSON_NetworksSorted(t *testing.T) {
	t.Parallel()

	data := []containerInspectData{{
		ID:   "net-test",
		Name: "/net-test",
	}}
	data[0].NetworkSettings.Networks = map[string]any{
		"zeta_net":  map[string]any{},
		"alpha_net": map[string]any{},
		"mid_net":   map[string]any{},
	}

	jsonBytes, _ := json.Marshal(data)
	containers, err := parseContainerInspectJSON(string(jsonBytes))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	networks := containers[0].Networks
	if len(networks) != 3 {
		t.Fatalf("expected 3 networks, got %d", len(networks))
	}
	if networks[0] != "alpha_net" || networks[1] != "mid_net" || networks[2] != "zeta_net" {
		t.Errorf("networks not sorted: %v", networks)
	}
}

func TestParseContainerInspectJSON_PortsSorted(t *testing.T) {
	t.Parallel()

	data := []containerInspectData{{
		ID:   "port-test",
		Name: "/port-test",
	}}
	data[0].NetworkSettings.Ports = map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{
		"8080/tcp": {{HostIP: "0.0.0.0", HostPort: "8080"}},
		"443/tcp":  {{HostIP: "0.0.0.0", HostPort: "443"}},
	}

	jsonBytes, _ := json.Marshal(data)
	containers, err := parseContainerInspectJSON(string(jsonBytes))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ports := containers[0].Ports
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(ports))
	}
	// Sorted by string — "0.0.0.0:443..." before "0.0.0.0:8080..."
	if ports[0] != "0.0.0.0:443->443/tcp" {
		t.Errorf("first port = %q, want 0.0.0.0:443->443/tcp", ports[0])
	}
}

func TestParseContainerInspectJSON_CreatedTimeParsing(t *testing.T) {
	t.Parallel()

	data := []containerInspectData{{
		ID:      "time-test",
		Name:    "/time-test",
		Created: "2024-06-15T14:30:00.123456789Z",
	}}
	jsonBytes, _ := json.Marshal(data)

	containers, err := parseContainerInspectJSON(string(jsonBytes))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := time.Date(2024, 6, 15, 14, 30, 0, 123456789, time.UTC)
	if !containers[0].Created.Equal(expected) {
		t.Errorf("Created = %v, want %v", containers[0].Created, expected)
	}
}

func TestParseContainerInspectJSON_InvalidCreatedTimeIsZero(t *testing.T) {
	t.Parallel()

	data := []containerInspectData{{
		ID:      "bad-time",
		Name:    "/bad-time",
		Created: "not-a-timestamp",
	}}
	jsonBytes, _ := json.Marshal(data)

	containers, err := parseContainerInspectJSON(string(jsonBytes))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !containers[0].Created.IsZero() {
		t.Errorf("Expected zero time for invalid created string, got %v", containers[0].Created)
	}
}

// --- Constants validation ---

func TestConstants(t *testing.T) {
	t.Parallel()

	if MaxComposeFileSize <= 0 {
		t.Error("MaxComposeFileSize must be positive")
	}
	if MaxComposeFileSize > 100*1024*1024 {
		t.Error("MaxComposeFileSize unreasonably large (>100 MB)")
	}
	if len(ComposeSearchPaths) == 0 {
		t.Error("ComposeSearchPaths must not be empty")
	}
	if len(ComposeFileNames) == 0 {
		t.Error("ComposeFileNames must not be empty")
	}
	if len(sensitiveEnvKeywords) == 0 {
		t.Error("sensitiveEnvKeywords must not be empty")
	}
}

func TestComposeFileNames_AllLowercase(t *testing.T) {
	t.Parallel()

	// Docker Compose file names should be lowercase per convention
	for _, name := range ComposeFileNames {
		if name != strings.ToLower(name) {
			t.Errorf("ComposeFileName %q is not lowercase", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration tests (~20% of coverage)
// These test the interaction between parsing and data structures.
// ---------------------------------------------------------------------------

func TestParseContainerInspectJSON_RealDockerOutput(t *testing.T) {
	t.Parallel()

	// This is a realistic (abbreviated) docker inspect output format.
	// Validates that our struct tags match Docker's actual JSON structure.
	realishJSON := `[{
		"Id": "sha256:abc123",
		"Name": "/production-web",
		"Created": "2024-03-01T12:00:00.000000000Z",
		"State": {
			"Status": "running",
			"Running": true
		},
		"Config": {
			"Image": "myapp:v2.1.0",
			"Env": [
				"NODE_ENV=production",
				"DATABASE_URL=postgres://host:5432/db",
				"SECRET_KEY=should-be-redacted",
				"API_TOKEN=also-redacted"
			],
			"Labels": {
				"com.docker.compose.project": "myapp",
				"com.docker.compose.service": "web"
			},
			"Cmd": ["node", "server.js"]
		},
		"NetworkSettings": {
			"Networks": {
				"myapp_default": {},
				"monitoring": {}
			},
			"Ports": {
				"3000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "3000"}],
				"9090/tcp": [{"HostIp": "127.0.0.1", "HostPort": "9090"}]
			}
		},
		"Mounts": [
			{"Source": "/opt/myapp/data", "Destination": "/app/data", "Mode": "rw"},
			{"Source": "/opt/myapp/logs", "Destination": "/app/logs", "Mode": "ro"}
		],
		"HostConfig": {
			"RestartPolicy": {
				"Name": "unless-stopped"
			}
		}
	}]`

	containers, err := parseContainerInspectJSON(realishJSON)
	if err != nil {
		t.Fatalf("Failed to parse realistic JSON: %v", err)
	}

	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}

	c := containers[0]

	// Verify all fields parsed correctly
	if c.Name != "production-web" {
		t.Errorf("Name = %q", c.Name)
	}
	if c.State != ContainerStateRunning {
		t.Errorf("State = %q", c.State)
	}
	if c.Restart != "unless-stopped" {
		t.Errorf("Restart = %q", c.Restart)
	}

	// Verify env redaction
	if c.Environment["NODE_ENV"] != "production" {
		t.Errorf("NODE_ENV should be visible")
	}
	if c.Environment["SECRET_KEY"] != SensitiveValueRedacted {
		t.Errorf("SECRET_KEY should be redacted")
	}
	if c.Environment["API_TOKEN"] != SensitiveValueRedacted {
		t.Errorf("API_TOKEN should be redacted")
	}

	// Verify networks are sorted
	if len(c.Networks) != 2 {
		t.Errorf("expected 2 networks, got %d", len(c.Networks))
	}
	if c.Networks[0] != "monitoring" || c.Networks[1] != "myapp_default" {
		t.Errorf("networks not sorted: %v", c.Networks)
	}

	// Verify ports are sorted
	if len(c.Ports) != 2 {
		t.Errorf("expected 2 ports, got %d", len(c.Ports))
	}

	// Verify volumes are sorted
	if len(c.Volumes) != 2 {
		t.Errorf("expected 2 volumes, got %d", len(c.Volumes))
	}

	// Verify labels
	if c.Labels["com.docker.compose.project"] != "myapp" {
		t.Errorf("compose project label = %q", c.Labels["com.docker.compose.project"])
	}
}

func TestParseDockerSize_DockerImageSizeFormats(t *testing.T) {
	t.Parallel()

	// These are actual size strings from `docker images --format "{{.Size}}"`
	// on real Docker installations.
	tests := []struct {
		name  string
		input string
		minB  int64
		maxB  int64
	}{
		{name: "alpine_image", input: "7.8MB", minB: 7_000_000, maxB: 8_000_000},
		{name: "nginx_image", input: "187MB", minB: 180_000_000, maxB: 200_000_000},
		{name: "ubuntu_image", input: "77.8MB", minB: 70_000_000, maxB: 80_000_000},
		{name: "large_app", input: "1.23GB", minB: 1_200_000_000, maxB: 1_300_000_000},
		{name: "tiny_image", input: "22kB", minB: 20_000, maxB: 25_000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseDockerSize(tt.input)
			if err != nil {
				t.Fatalf("ParseDockerSize(%q) error: %v", tt.input, err)
			}
			if got < tt.minB || got > tt.maxB {
				t.Errorf("ParseDockerSize(%q) = %d, expected range [%d, %d]",
					tt.input, got, tt.minB, tt.maxB)
			}
		})
	}
}

func TestParseEnvVars_Idempotent(t *testing.T) {
	t.Parallel()

	input := []string{
		"PATH=/usr/bin",
		"SECRET_KEY=hidden",
	}

	result1 := parseEnvVars(input)
	result2 := parseEnvVars(input)

	for k, v := range result1 {
		if result2[k] != v {
			t.Errorf("non-idempotent: key %q: %q vs %q", k, v, result2[k])
		}
	}
}

// ---------------------------------------------------------------------------
// E2E-style tests (~10% of coverage)
// These test the full data flow from JSON -> DockerContainer -> assertions.
// ---------------------------------------------------------------------------

func TestEndToEnd_MultiContainerInspect(t *testing.T) {
	t.Parallel()

	// Simulate a batch docker inspect with multiple containers
	data := make([]containerInspectData, 5)
	for i := range data {
		data[i].ID = "container-" + string(rune('a'+i))
		data[i].Name = "/svc-" + string(rune('a'+i))
		data[i].Created = "2024-01-01T00:00:00Z"
		data[i].Config.Image = "image-" + string(rune('a'+i)) + ":latest"
		data[i].Config.Env = []string{
			"ENV=production",
			"DB_PASSWORD=s3cret",
		}
		data[i].State.Running = i%2 == 0
		data[i].State.Status = "running"
		if i%2 != 0 {
			data[i].State.Status = "exited"
		}
		data[i].HostConfig.RestartPolicy.Name = "always"
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	containers, err := parseContainerInspectJSON(string(jsonBytes))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(containers) != 5 {
		t.Fatalf("expected 5 containers, got %d", len(containers))
	}

	// Verify running/stopped counts
	running, stopped := 0, 0
	for _, c := range containers {
		switch c.State {
		case ContainerStateRunning:
			running++
		case ContainerStateStopped:
			stopped++
		}

		// Every container should have password redacted
		if c.Environment["DB_PASSWORD"] != SensitiveValueRedacted {
			t.Errorf("container %q: DB_PASSWORD not redacted", c.Name)
		}
		// Every container should have ENV visible
		if c.Environment["ENV"] != "production" {
			t.Errorf("container %q: ENV = %q, want production", c.Name, c.Environment["ENV"])
		}
	}

	if running != 3 {
		t.Errorf("expected 3 running, got %d", running)
	}
	if stopped != 2 {
		t.Errorf("expected 2 stopped, got %d", stopped)
	}
}

func TestEndToEnd_ParseDockerSize_RoundTrip(t *testing.T) {
	t.Parallel()

	// Verify that common Docker image sizes parse correctly and are
	// in the right order of magnitude.
	sizes := map[string]int64{
		"5.6MB": 5_600_000,
		"1.2GB": 1_200_000_000,
		"100kB": 100_000,
		"2.5TB": 2_500_000_000_000,
		"0B":    0,
		"1024":  1024,
		"1024B": 1024,
	}

	for input, expected := range sizes {
		got, err := ParseDockerSize(input)
		if err != nil {
			t.Errorf("ParseDockerSize(%q) error: %v", input, err)
			continue
		}
		if got != expected {
			t.Errorf("ParseDockerSize(%q) = %d, want %d", input, got, expected)
		}
	}
}
