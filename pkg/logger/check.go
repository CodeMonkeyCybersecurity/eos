/* pkg/logger/check.go */

package logger

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"os"
	"path/filepath"
)

func EnsureLogPermissions(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, shared.SecretDirPerm); err != nil {
		return err
	}
	if err := os.Chmod(dir, shared.SecretDirPerm); err != nil {
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
	return os.Chmod(path, shared.SecretFilePerm)
}

func IsStrict(strict []bool) bool {
	return len(strict) > 0 && strict[0]
}
