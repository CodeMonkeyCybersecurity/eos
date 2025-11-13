package repository

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const preferencesFileName = "create-repo.yaml"

// PreferencesPath returns the path used to persist repository preferences.
func PreferencesPath(repoPath string) string {
	return filepath.Join(repoPath, ".eos", preferencesFileName)
}

// LoadRepoPreferences loads persisted repository preferences if present.
func LoadRepoPreferences(path string) (*RepoPreferences, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var prefs RepoPreferences
	if err := yaml.Unmarshal(data, &prefs); err != nil {
		return nil, err
	}
	return &prefs, nil
}

// SaveRepoPreferences persists repository preferences to disk.
func SaveRepoPreferences(path string, prefs *RepoPreferences) error {
	if prefs == nil {
		return nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	payload, err := yaml.Marshal(prefs)
	if err != nil {
		return err
	}

	return os.WriteFile(path, payload, 0o644)
}
