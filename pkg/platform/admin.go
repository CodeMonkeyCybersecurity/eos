// pkg/platform/admin.go
package platform

import (
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func GuessAdminGroup(ctx context.Context) string {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "sudo"
	}
	defer func() {
		if err := file.Close(); err != nil {
			otelzap.Ctx(ctx).Warn("Failed to close log file", zap.Error(err))
		}
	}()

	scanner := bufio.NewScanner(file)
	var idLike string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID_LIKE=") {
			idLike = strings.Trim(strings.SplitN(line, "=", 2)[1], `"`)
			break
		}
	}
	if strings.Contains(idLike, "rhel") || strings.Contains(idLike, "fedora") {
		return "wheel"
	}
	return "sudo"
}
