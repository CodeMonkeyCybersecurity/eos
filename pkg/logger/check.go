/* pkg/logger/check.go */

package logger

import (
	"os"
	"path/filepath"
)

func EnsureLogPermissions(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		if cerr := f.Close(); cerr != nil {
			return cerr
		}
	}
	return os.Chmod(path, 0600)
}

func IsStrict(strict []bool) bool {
	return len(strict) > 0 && strict[0]
}
