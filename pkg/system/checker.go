/* pkg/system/checker.go */
package system

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// Exists returns true if the file or directory at the given path exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}

// LookupUser returns the UID and GID of the given user.
func LookupUser(name string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("user lookup failed: %w", err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid UID: %w", err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid GID: %w", err)
	}
	return uid, gid, nil
}


/**/
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
/**/