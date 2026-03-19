package chatarchive

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/parse"
)

// ResolveOptions applies defaults, expands home directories, converts
// paths to absolute form, and removes duplicate source roots.
func ResolveOptions(opts Options) (Options, error) {
	resolved := Options{
		Sources: opts.Sources,
		Dest:    opts.Dest,
		DryRun:  opts.DryRun,
	}

	if len(resolved.Sources) == 0 {
		resolved.Sources = DefaultSources()
	}
	if strings.TrimSpace(resolved.Dest) == "" {
		resolved.Dest = DefaultDest()
	}

	dest, err := resolvePath(resolved.Dest)
	if err != nil {
		return Options{}, fmt.Errorf("resolve destination %q: %w", resolved.Dest, err)
	}
	resolved.Dest = dest

	seen := make(map[string]struct{}, len(resolved.Sources))
	dedupedSources := make([]string, 0, len(resolved.Sources))
	for _, source := range resolved.Sources {
		if strings.TrimSpace(source) == "" {
			continue
		}

		path, err := resolvePath(source)
		if err != nil {
			return Options{}, fmt.Errorf("resolve source %q: %w", source, err)
		}
		if path == resolved.Dest {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		dedupedSources = append(dedupedSources, path)
	}

	resolved.Sources = dedupedSources
	return resolved, nil
}

func resolvePath(path string) (string, error) {
	expanded := parse.ExpandHome(strings.TrimSpace(path))
	cleaned := filepath.Clean(expanded)
	absolute, err := filepath.Abs(cleaned)
	if err != nil {
		return "", err
	}
	return absolute, nil
}
