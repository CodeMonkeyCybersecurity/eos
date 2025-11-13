// pkg/crypto/bcrypt.go

package crypto

import (
	"errors"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes the given password using bcrypt at the default cost (10).
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.New("bcrypt hash failed: " + err.Error())
	}
	return string(hash), nil
}

// HashPasswordWithCost hashes a password with a custom cost.
func HashPasswordWithCost(password string, cost int) (string, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return "", errors.New("bcrypt: invalid cost parameter")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", errors.New("bcrypt hash failed: " + err.Error())
	}
	return string(hash), nil
}

// ComparePassword checks if password matches the bcrypt hash.
func ComparePassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// ComparePasswordBool returns true if password matches hash, false otherwise.
// Only use when you don't care about *why* it failed.
func ComparePasswordBool(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// IsHashCostWeak checks if a hash uses less than minCost rounds (e.g., upgrade on login).
func IsHashCostWeak(hash string, minCost int) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return true // treat errors as "unsafe"
	}
	return cost < minCost
}

func ComparePasswordLogging(hash, password string, logger *zap.Logger) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil && logger != nil {
		logger.Warn("bcrypt password mismatch", zap.Error(err))
	}
	return err == nil
}
