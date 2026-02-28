package create

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

type chatArchiveEntry struct {
	SourcePath   string `json:"source_path"`
	DestPath     string `json:"dest_path"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	DuplicateOf  string `json:"duplicate_of,omitempty"`
	Copied       bool   `json:"copied"`
	Conversation string `json:"conversation,omitempty"`
}

type chatArchiveManifest struct {
	GeneratedAt string             `json:"generated_at"`
	Sources     []string           `json:"sources"`
	DestDir     string             `json:"dest_dir"`
	Entries     []chatArchiveEntry `json:"entries"`
}

var CreateChatArchiveCmd = &cobra.Command{
	Use:   "chat-archive",
	Short: "Copy and deduplicate chat transcripts into a local archive",
	Long: `Find transcript-like files (jsonl/json/html), copy unique files into one archive,
and write an index manifest with duplicate mappings.

Examples:
  eos create chat-archive
  eos create chat-archive --source ~/.openclaw/agents/main/sessions --source ~/dev
  eos create chat-archive --dest ~/Dev/eos/outputs/chat-archive --dry-run`,
	RunE: eos.Wrap(runCreateChatArchive),
}

func init() {
	CreateCmd.AddCommand(CreateChatArchiveCmd)
	CreateChatArchiveCmd.Flags().StringSlice("source", []string{"~/.openclaw/agents/main/sessions", "~/dev"}, "Source directories to scan")
	CreateChatArchiveCmd.Flags().String("dest", "~/Dev/eos/outputs/chat-archive", "Destination archive directory")
	CreateChatArchiveCmd.Flags().Bool("dry-run", false, "Show what would be archived without copying files")
}

func runCreateChatArchive(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	sources, _ := cmd.Flags().GetStringSlice("source")
	dest, _ := cmd.Flags().GetString("dest")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	expandedSources := make([]string, 0, len(sources))
	for _, s := range sources {
		expandedSources = append(expandedSources, expandHome(s))
	}
	dest = expandHome(dest)

	if !dryRun {
		if err := os.MkdirAll(dest, 0o755); err != nil {
			return fmt.Errorf("create destination dir: %w", err)
		}
	}

	files, err := discoverTranscriptFiles(expandedSources, dest)
	if err != nil {
		return err
	}

	byHash := map[string]string{}
	manifest := chatArchiveManifest{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Sources:     expandedSources,
		DestDir:     dest,
		Entries:     make([]chatArchiveEntry, 0, len(files)),
	}

	copied := 0
	dups := 0
	for _, src := range files {
		hash, size, err := fileSHA256(src)
		if err != nil {
			continue
		}
		if size == 0 {
			continue // skip empty transcript artifacts
		}

		conversation := strings.TrimSuffix(filepath.Base(src), filepath.Ext(src))
		entry := chatArchiveEntry{SourcePath: src, SHA256: hash, SizeBytes: size, Conversation: conversation}

		if firstDest, ok := byHash[hash]; ok {
			entry.DuplicateOf = firstDest
			entry.DestPath = firstDest
			entry.Copied = false
			dups++
			manifest.Entries = append(manifest.Entries, entry)
			continue
		}

		ext := filepath.Ext(src)
		if ext == "" {
			ext = ".bin"
		}
		slug := sanitizeName(strings.TrimSuffix(filepath.Base(src), filepath.Ext(src)))
		if slug == "" {
			slug = "chat"
		}
		destFile := filepath.Join(dest, fmt.Sprintf("%s-%s%s", hash[:12], slug, ext))
		entry.DestPath = destFile
		entry.Copied = true

		if !dryRun {
			if err := copyArchiveFile(src, destFile); err != nil {
				return fmt.Errorf("copy %s -> %s: %w", src, destFile, err)
			}
		}

		byHash[hash] = destFile
		copied++
		manifest.Entries = append(manifest.Entries, entry)
	}

	if !dryRun {
		manifestPath := filepath.Join(dest, "manifest.json")
		b, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal manifest: %w", err)
		}
		if err := os.WriteFile(manifestPath, b, 0o644); err != nil {
			return fmt.Errorf("write manifest: %w", err)
		}
		fmt.Printf("Archive complete. %d unique files copied, %d duplicates mapped.\n", copied, dups)
		fmt.Printf("Manifest: %s\n", manifestPath)
	} else {
		fmt.Printf("Dry run complete. %d unique files, %d duplicates.\n", copied, dups)
	}

	_ = rc
	return nil
}

func discoverTranscriptFiles(roots []string, dest string) ([]string, error) {
	out := make([]string, 0)
	seen := map[string]struct{}{}
	destAbs := strings.ToLower(filepath.Clean(dest))

	isCandidate := func(path string) bool {
		lp := strings.ToLower(path)
		base := strings.ToLower(filepath.Base(path))

		// Strong path clues first
		hasPathClue := strings.Contains(lp, "/.openclaw/") || strings.Contains(lp, "/sessions/") || strings.Contains(lp, "/transcripts/") || strings.Contains(lp, "/chats/") || strings.Contains(lp, "conversation")

		if strings.HasSuffix(lp, ".jsonl") {
			return hasPathClue || strings.Contains(base, "chat") || strings.Contains(base, "session") || strings.Contains(base, "conversation") || strings.Contains(base, "transcript")
		}
		if strings.HasSuffix(lp, ".chat") {
			return true
		}
		if strings.HasSuffix(lp, ".html") {
			return strings.Contains(base, "chat") || strings.Contains(base, "conversation") || strings.Contains(base, "transcript")
		}
		if strings.HasSuffix(lp, ".json") {
			if !hasPathClue && !strings.Contains(base, "chat") && !strings.Contains(base, "conversation") && !strings.Contains(base, "session") && !strings.Contains(base, "transcript") {
				return false
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return false
			}
			h := strings.ToLower(string(b))
			hasMessages := strings.Contains(h, "\"messages\"")
			hasRole := strings.Contains(h, "\"role\"")
			hasContent := strings.Contains(h, "\"content\"")
			hasConversation := strings.Contains(h, "\"conversation\"")
			return (hasMessages && (hasRole || hasContent)) || (hasConversation && hasContent)
		}
		return false
	}

	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			lpath := strings.ToLower(filepath.Clean(path))
			if lpath == destAbs || strings.HasPrefix(lpath, destAbs+"/") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.Contains(lpath, "/dev/eos/outputs/chat-archive") || strings.Contains(lpath, "/desktop/conversationarchive") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				name := strings.ToLower(d.Name())
				if name == ".git" || name == "node_modules" || name == "target" || name == "vendor" || name == ".cache" {
					return filepath.SkipDir
				}
				return nil
			}
			if isCandidate(path) {
				if _, ok := seen[path]; !ok {
					seen[path] = struct{}{}
					out = append(out, path)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	sort.Strings(out)
	return out, nil
}

func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func copyArchiveFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func sanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune('-')
		case r == ' ':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}
