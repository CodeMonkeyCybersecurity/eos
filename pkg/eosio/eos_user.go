// pkg/eosio/eos_user.go

package eosio

import (
    "fmt"
    "os/user"

    "go.uber.org/zap"
)

// CheckEffectiveUser ensures the current process is running as the expected user.
// It does NOT attempt privilege escalation.
func CheckEffectiveUser(expected string) error {
    currentUser, err := user.Current()
    if err != nil {
        zap.L().Error("Failed to detect current user", zap.Error(err))
        return err
    }

    if currentUser.Username != expected {
        return fmt.Errorf("this command must be run as '%s' user, but current user is '%s'", expected, currentUser.Username)
    }

    zap.L().Info("✅ Running under correct user", zap.String("user", currentUser.Username))
    return nil
}