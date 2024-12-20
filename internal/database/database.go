package database

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gocql/gocql"
	_ "github.com/joho/godotenv/autoload"
)

type User struct {
	ID           gocql.UUID `json:"id"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type APIKey struct {
	ID         gocql.UUID `json:"id"`
	UserID     gocql.UUID `json:"user_id"`
	Name       string     `json:"name"`
	KeyHash    string     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	IsActive   bool       `json:"is_active"`
}

type Service interface {
	Health() map[string]string
	Close() error

	CreateUser(email, passwordHash string) (*User, error)
	GetUserByEmail(email string) (*User, error)
	GetUserByID(id gocql.UUID) (*User, error)

	CreateAPIKey(userID gocql.UUID, name, keyHash string, expiresAt *time.Time) (*APIKey, error)
	GetAPIKeyByHash(keyHash string) (*APIKey, error)
	ListAPIKeys(userID gocql.UUID) ([]APIKey, error)
	UpdateAPIKeyLastUsed(keyID gocql.UUID) error
	RevokeAPIKey(userID, keyID gocql.UUID) error
	DeleteAPIKey(userID, keyID gocql.UUID) error
}

type service struct {
	session *gocql.Session
}

func New() Service {
	// Load environment variables
	cassandraHost := os.Getenv("CASSANDRA_HOST")
	cassandraUsername := os.Getenv("CASSANDRA_USERNAME")
	cassandraPassword := os.Getenv("CASSANDRA_PASSWORD")
	cassandraCaPath := os.Getenv("CASSANDRA_CA_PATH")
	cassandraKeyspace := os.Getenv("CASSANDRA_KEYSPACE")

	cluster := gocql.NewCluster(cassandraHost)
	cluster.Port = 9142
	cluster.Authenticator = gocql.PasswordAuthenticator{
		Username: cassandraUsername,
		Password: cassandraPassword,
	}
	cluster.SslOpts = &gocql.SslOptions{
		CaPath:                 cassandraCaPath,
		EnableHostVerification: false,
	}
	cluster.Consistency = gocql.LocalQuorum
	cluster.Keyspace = cassandraKeyspace

	session, err := cluster.CreateSession()
	if err != nil {
		log.Fatal("Failed to create Cassandra session:", err)
	}

	return &service{session: session}
}

func (s *service) Health() map[string]string {
	stats := make(map[string]string)

	if err := s.session.Query("SELECT release_version FROM system.local").Exec(); err != nil {
		stats["status"] = "down"
		stats["error"] = fmt.Sprintf("Cassandra down: %v", err)
		return stats
	}

	stats["status"] = "up"
	stats["message"] = "Cassandra is healthy"
	return stats
}

func (s *service) Close() error {
	s.session.Close()
	return nil
}

// User operations
func (s *service) CreateUser(email, passwordHash string) (*User, error) {
	user := &User{
		ID:           gocql.TimeUUID(),
		Email:        email,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.session.Query(`
								INSERT INTO users (id, email, password_hash, created_at, updated_at)
								VALUES (?, ?, ?, ?, ?)`,
		user.ID, user.Email, user.PasswordHash, user.CreatedAt, user.UpdatedAt,
	).Exec(); err != nil {
		return nil, fmt.Errorf("error creating user: %w", err)
	}

	return user, nil
}

func (s *service) GetUserByEmail(email string) (*User, error) {
	var user User
	if err := s.session.Query(`
								SELECT id, email, password_hash, created_at, updated_at
								FROM users WHERE email = ? ALLOW FILTERING`,
		email,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt); err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	return &user, nil
}

func (s *service) GetUserByID(id gocql.UUID) (*User, error) {
	var user User
	if err := s.session.Query(`
								SELECT id, email, password_hash, created_at, updated_at
								FROM users WHERE id = ?`,
		id,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt); err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	return &user, nil
}

// API Key-related query implementations
func (s *service) CreateAPIKey(userID gocql.UUID, name, keyHash string, expiresAt *time.Time) (*APIKey, error) {
	apiKey := &APIKey{
		ID:        gocql.TimeUUID(),
		UserID:    userID,
		Name:      name,
		KeyHash:   keyHash,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		IsActive:  true,
	}

	if err := s.session.Query(`
								INSERT INTO api_keys (id, user_id, name, key_hash, created_at, expires_at, is_active)
								VALUES (?, ?, ?, ?, ?, ?, ?)`,
		apiKey.ID, apiKey.UserID, apiKey.Name, apiKey.KeyHash,
		apiKey.CreatedAt, apiKey.ExpiresAt, apiKey.IsActive,
	).Exec(); err != nil {
		return nil, fmt.Errorf("error creating API key: %w", err)
	}

	return apiKey, nil
}

func (s *service) GetAPIKeyByHash(keyHash string) (*APIKey, error) {
	var apiKey APIKey
	if err := s.session.Query(`
								SELECT id, user_id, name, key_hash, created_at, last_used_at, expires_at, is_active
								FROM api_keys WHERE key_hash = ? ALLOW FILTERING`,
		keyHash,
	).Scan(
		&apiKey.ID, &apiKey.UserID, &apiKey.Name, &apiKey.KeyHash,
		&apiKey.CreatedAt, &apiKey.LastUsedAt, &apiKey.ExpiresAt, &apiKey.IsActive,
	); err != nil {
		return nil, fmt.Errorf("API key not found: %w", err)
	}
	return &apiKey, nil
}

func (s *service) ListAPIKeys(userID gocql.UUID) ([]APIKey, error) {
	iter := s.session.Query(`
								SELECT id, user_id, name, key_hash, created_at, last_used_at, expires_at, is_active
								FROM api_keys WHERE user_id = ? ALLOW FILTERING`,
		userID,
	).Iter()

	var apiKeys []APIKey
	var apiKey APIKey

	for iter.Scan(
		&apiKey.ID, &apiKey.UserID, &apiKey.Name, &apiKey.KeyHash,
		&apiKey.CreatedAt, &apiKey.LastUsedAt, &apiKey.ExpiresAt, &apiKey.IsActive,
	) {
		apiKeys = append(apiKeys, apiKey)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("error listing API keys: %w", err)
	}

	return apiKeys, nil
}

func (s *service) UpdateAPIKeyLastUsed(keyID gocql.UUID) error {
	now := time.Now()
	if err := s.session.Query(`
								UPDATE api_keys SET last_used_at = ? WHERE id = ?`,
		now, keyID,
	).Exec(); err != nil {
		return fmt.Errorf("error updating API key last used: %w", err)
	}
	return nil
}

func (s *service) RevokeAPIKey(userID, keyID gocql.UUID) error {
	// First verify the API key belongs to the user
	var count int
	if err := s.session.Query(`
								SELECT COUNT(*) FROM api_keys
								WHERE id = ? AND user_id = ? ALLOW FILTERING`,
		keyID, userID,
	).Scan(&count); err != nil {
		return fmt.Errorf("error verifying API key ownership: %w", err)
	}

	if count == 0 {
		return fmt.Errorf("API key not found or not owned by user")
	}

	// Update the is_active status
	if err := s.session.Query(`
								UPDATE api_keys SET is_active = ? WHERE id = ?`,
		false, keyID,
	).Exec(); err != nil {
		return fmt.Errorf("error revoking API key: %w", err)
	}

	return nil
}

func (s *service) DeleteAPIKey(userID, keyID gocql.UUID) error {
	// First verify the API key belongs to the user
	var apiKey APIKey
	if err := s.session.Query(`
								SELECT id, user_id FROM api_keys
								WHERE id = ? ALLOW FILTERING`,
		keyID,
	).Scan(&apiKey.ID, &apiKey.UserID); err != nil {
		return fmt.Errorf("API key not found: %w", err)
	}

	if apiKey.UserID != userID {
		return fmt.Errorf("API key not owned by user")
	}

	// Delete the API key
	if err := s.session.Query(`
								DELETE FROM api_keys WHERE id = ?`,
		keyID,
	).Exec(); err != nil {
		return fmt.Errorf("error deleting API key: %w", err)
	}

	return nil
}
