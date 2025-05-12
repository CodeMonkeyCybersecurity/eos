// pkg/vault/vault.go

package vault

import (
	"fmt"
	"os"
	"strings"
)

func Get(key string) (string, error) {
	envVar := "EOS_SECRET_" + sanitizeKey(key)
	if val := os.Getenv(envVar); val != "" {
		return val, nil
	}
	return "", fmt.Errorf("vault stub: missing secret for %s", key)
}

func sanitizeKey(k string) string {
	return strings.ToUpper(strings.ReplaceAll(k, "/", "_"))
}
