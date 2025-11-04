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
