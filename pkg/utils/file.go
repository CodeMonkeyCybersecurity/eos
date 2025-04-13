// pkg/utils/utils.go

package utils

import (
	"os"
)

//
//---------------------------- FILE COMMANDS ---------------------------- //
//

// BackupFile makes a simple timestamped backup of the original file.
func BackupFile(path string) error {
	backupPath := path + ".bak"
	input, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(backupPath, input, 0644)
}

// CatFile prints the content of a file
func CatFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}
