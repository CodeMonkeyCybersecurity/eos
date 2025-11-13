package repository

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGitWrapperHasCommits(t *testing.T) {
	dir := t.TempDir()

	g := &GitWrapper{Path: dir}

	if err := g.InitRepository(); err != nil {
		t.Fatalf("init repository: %v", err)
	}

	has, err := g.HasCommits()
	if err != nil {
		t.Fatalf("HasCommits returned error for empty repo: %v", err)
	}
	if has {
		t.Fatalf("expected HasCommits to be false for empty repository")
	}

	if _, err := g.run("config", "user.email", "test@example.com"); err != nil {
		t.Fatalf("set git user.email: %v", err)
	}
	if _, err := g.run("config", "user.name", "Test User"); err != nil {
		t.Fatalf("set git user.name: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if _, err := g.run("add", "."); err != nil {
		t.Fatalf("git add: %v", err)
	}
	if _, err := g.run("commit", "-m", "initial"); err != nil {
		t.Fatalf("git commit: %v", err)
	}

	has, err = g.HasCommits()
	if err != nil {
		t.Fatalf("HasCommits returned error after commit: %v", err)
	}
	if !has {
		t.Fatalf("expected HasCommits to be true after commit")
	}
}

func TestValidateBranchName(t *testing.T) {
	tests := []struct {
		name      string
		branch    string
		wantError bool
	}{
		// Valid branch names
		{"simple name", "main", false},
		{"with dash", "feature-branch", false},
		{"with underscore", "feature_branch", false},
		{"with slash", "feature/my-branch", false},
		{"with numbers", "release-1.0.0", false},
		{"develop", "develop", false},

		// Invalid branch names
		{"empty", "", true},
		{"single @", "@", true},
		{"backslash", "\\", true},
		{"with backslash", "feature\\branch", true},
		{"with question mark", "feature?branch", true},
		{"with asterisk", "feature*branch", true},
		{"with tilde", "feature~branch", true},
		{"with caret", "feature^branch", true},
		{"with colon", "feature:branch", true},
		{"with at-brace", "feature@{branch", true},
		{"with double dot", "feature..branch", true},
		{"with double slash", "feature//branch", true},
		{"starts with dot", ".feature", true},
		{"ends with dot", "feature.", true},
		{"ends with .lock", "feature.lock", true},
		{"with space", "feature branch", true},
		{"with tab", "feature\tbranch", true},
		{"with newline", "feature\nbranch", true},
		{"too long", string(make([]byte, 256)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBranchName(tt.branch)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateBranchName(%q) error = %v, wantError %v", tt.branch, err, tt.wantError)
			}
		})
	}
}

func TestValidateRepoName(t *testing.T) {
	tests := []struct {
		name      string
		repoName  string
		wantError bool
	}{
		// Valid repository names
		{"simple name", "myrepo", false},
		{"with dash", "my-repo", false},
		{"with underscore", "my_repo", false},
		{"with dot", "my.repo", false},
		{"with numbers", "repo123", false},
		{"mixed", "my-project_1.0", false},

		// Invalid repository names
		{"empty", "", true},
		{"too long", string(make([]byte, 101)), true},
		{"reserved dot", ".", true},
		{"reserved dotdot", "..", true},
		{"reserved dash", "-", true},
		{"reserved underscore", "_", true},
		{"reserved assets", "assets", true},
		{"reserved api", "api", true},
		{"reserved admin", "ADMIN", true}, // Case insensitive
		{"path traversal", "../etc/passwd", true},
		{"consecutive dots", "my..repo", true},
		{"with space", "my repo", true},
		{"with slash", "my/repo", true},
		{"with backslash", "my\\repo", true},
		{"starts with dot", ".myrepo", true},
		{"starts with dash", "-myrepo", true},
		{"starts with underscore", "_myrepo", true},
		{"ends with dot", "myrepo.", true},
		{"ends with dash", "myrepo-", true},
		{"ends with underscore", "myrepo_", true},
		{"special chars", "my@repo", true},
		{"sql injection attempt", "'; DROP TABLE;", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRepoName(tt.repoName)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateRepoName(%q) error = %v, wantError %v", tt.repoName, err, tt.wantError)
			}
		})
	}
}

func TestSanitizeInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"clean text", "hello world", "hello world"},
		{"with ANSI color", "\x1b[31mred text\x1b[0m", "red text"},
		{"with ANSI clear", "\x1b[2Jclear", "clear"},
		{"with control chars", "hello\x00\x01world", "helloworld"},
		{"with tabs", "hello\tworld", "hello\tworld"},   // Tabs allowed
		{"with newlines", "hello\nworld", "helloworld"}, // Newlines stripped
		{"mixed", "\x1b[1mbold\x1b[0m and \x00clean", "bold and clean"},
		{"empty", "", ""},
		{"only escape", "\x1b[0m", ""},
		{"leading/trailing space", "  hello  ", "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeInput(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeInput(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
