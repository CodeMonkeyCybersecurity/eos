package repository

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadRepoPreferences(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.yaml")

	prefs := &RepoPreferences{
		Remote:          "origin",
		Branch:          "develop",
		Organization:    "codemonkey",
		DefaultPrivate:  true,
		RememberPrivate: true,
	}

	if err := SaveRepoPreferences(path, prefs); err != nil {
		t.Fatalf("SaveRepoPreferences returned error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected preferences file to exist: %v", err)
	}
	if info.Size() == 0 {
		t.Fatalf("expected preferences file to have content")
	}

	loaded, err := LoadRepoPreferences(path)
	if err != nil {
		t.Fatalf("LoadRepoPreferences returned error: %v", err)
	}

	if loaded == nil {
		t.Fatalf("expected preferences to load")
	}

	if loaded.Remote != prefs.Remote {
		t.Errorf("Remote mismatch: got %s want %s", loaded.Remote, prefs.Remote)
	}
	if loaded.Branch != prefs.Branch {
		t.Errorf("Branch mismatch: got %s want %s", loaded.Branch, prefs.Branch)
	}
	if loaded.Organization != prefs.Organization {
		t.Errorf("Organization mismatch: got %s want %s", loaded.Organization, prefs.Organization)
	}
	if loaded.DefaultPrivate != prefs.DefaultPrivate {
		t.Errorf("DefaultPrivate mismatch: got %v want %v", loaded.DefaultPrivate, prefs.DefaultPrivate)
	}
	if loaded.RememberPrivate != prefs.RememberPrivate {
		t.Errorf("RememberPrivate mismatch: got %v want %v", loaded.RememberPrivate, prefs.RememberPrivate)
	}
}
