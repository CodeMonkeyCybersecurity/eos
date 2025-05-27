package git

import (
	"fmt"
	"os"

	git "github.com/go-git/go-git/v5"
)

// Clone clones the given repository URL into the specified local path.
func Clone(repoURL, targetPath string) error {
	if _, err := os.Stat(targetPath); err == nil {
		return fmt.Errorf("target path %s already exists", targetPath)
	}

	_, err := git.PlainClone(targetPath, false, &git.CloneOptions{
		URL:      repoURL,
		Progress: os.Stdout,
	})
	if err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}
	return nil
}