// pkg/chatarchive/manifest.go

package chatarchive

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// Entry represents a single file in the chat archive manifest.
type Entry struct {
	SourcePath   string `json:"source_path"`
	DestPath     string `json:"dest_path"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	DuplicateOf  string `json:"duplicate_of,omitempty"`
	Copied       bool   `json:"copied"`
	Conversation string `json:"conversation,omitempty"`
}

// Manifest is the top-level archive manifest written to dest/manifest.json.
type Manifest struct {
	GeneratedAt string   `json:"generated_at"`
	Sources     []string `json:"sources"`
	DestDir     string   `json:"dest_dir"`
	Entries     []Entry  `json:"entries"`
}

// ManifestPath returns the canonical manifest path within a dest directory.
func ManifestPath(destDir string) string {
	return filepath.Join(destDir, "manifest.json")
}

// ReadManifest reads and parses an existing manifest from disk.
// Returns nil, nil if the file does not exist (not-found is not an error).
func ReadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// RecoverManifest moves a corrupt manifest aside so the archive can
// self-heal on the next write.
func RecoverManifest(path string) (string, error) {
	recoveredPath := fmt.Sprintf("%s.corrupt-%s", path, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.Rename(path, recoveredPath); err != nil {
		return "", fmt.Errorf("move corrupt manifest aside: %w", err)
	}
	return recoveredPath, nil
}

// WriteManifest serialises the manifest to disk atomically.
func WriteManifest(path string, m *Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("create manifest dir: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, "manifest-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp manifest: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(shared.ConfigFilePerm); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp manifest: %w", err)
	}
	if _, err := tmpFile.Write(b); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp manifest: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temp manifest: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp manifest: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace manifest: %w", err)
	}

	dirHandle, err := os.Open(dir)
	if err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	cleanup = false
	return nil
}

// ExistingHashes extracts a hash->destPath map from an existing manifest
// for idempotent merge checks.
func ExistingHashes(m *Manifest) map[string]string {
	if m == nil {
		return make(map[string]string)
	}
	hashes := make(map[string]string, len(m.Entries))
	for _, e := range m.Entries {
		if e.SHA256 != "" && e.Copied {
			hashes[e.SHA256] = e.DestPath
		}
	}
	return hashes
}

// MergeEntries merges new entries into an existing manifest, preserving
// existing entries and only adding new unique files.
func MergeEntries(existing *Manifest, newEntries []Entry) *Manifest {
	if existing == nil {
		return &Manifest{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Entries:     newEntries,
		}
	}

	seen := make(map[string]struct{}, len(existing.Entries))
	for _, e := range existing.Entries {
		if e.SHA256 == "" {
			continue
		}
		seen[e.SHA256] = struct{}{}
	}

	merged := make([]Entry, len(existing.Entries))
	copy(merged, existing.Entries)

	for _, ne := range newEntries {
		if _, ok := seen[ne.SHA256]; !ok {
			merged = append(merged, ne)
			seen[ne.SHA256] = struct{}{}
		}
	}

	existing.Entries = merged
	existing.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	return existing
}
