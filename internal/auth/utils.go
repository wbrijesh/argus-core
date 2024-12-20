package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	APIKeyPrefix = "argus"
	APIKeyBytes  = 32
)

// GenerateAPIKey generates a new API key with format: argus_<random-string> base64 encoded
// The random string is base64 encoded and URL safe
func GenerateAPIKey() (string, error) {
	// Generate random bytes
	randomBytes := make([]byte, APIKeyBytes)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode as base64 and make it URL safe
	// Use RawURLEncoding to avoid special characters like '/' and '+'
	randomString := base64.RawURLEncoding.EncodeToString(randomBytes)

	// Format: argus_<random-string>
	return fmt.Sprintf("%s_%s", APIKeyPrefix, randomString), nil
}

// HashAPIKey creates a SHA-256 hash of the API key
// This is what we'll store in the database
func HashAPIKey(key string) string {
	// Create SHA-256 hash
	hasher := sha256.New()
	hasher.Write([]byte(key))

	// Convert to hex string
	return hex.EncodeToString(hasher.Sum(nil))
}

// validateAPIKeyFormat checks if the API key has the correct format
func validateAPIKeyFormat(key string) bool {
	// Check if key starts with the correct prefix
	if len(key) < len(APIKeyPrefix)+2 { // +2 for '_' and at least one character
		return false
	}

	prefix := key[:len(APIKeyPrefix)]
	if prefix != APIKeyPrefix {
		return false
	}

	// Check if the next character is underscore
	if key[len(APIKeyPrefix)] != '_' {
		return false
	}

	return true
}
