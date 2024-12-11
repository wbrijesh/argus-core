package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/joho/godotenv/autoload"
)

type User struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// APIKey represents an API key in the database
type APIKey struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	Name       string     `json:"name"`
	KeyHash    string     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	IsActive   bool       `json:"is_active"`
}

// Service represents a service that interacts with a database.
type Service interface {
	// Health returns a map of health status information.
	Health() map[string]string

	// Close terminates the database connection.
	Close() error

	// User-related queries
	CreateUser(email, passwordHash string) (*User, error)
	GetUserByEmail(email string) (*User, error)
	GetUserByID(id uuid.UUID) (*User, error)

	// API Key-related queries
	CreateAPIKey(userID uuid.UUID, name, keyHash string, expiresAt *time.Time) (*APIKey, error)
	GetAPIKeyByHash(keyHash string) (*APIKey, error)
	ListAPIKeys(userID uuid.UUID) ([]APIKey, error)
	UpdateAPIKeyLastUsed(keyID uuid.UUID) error
	RevokeAPIKey(userID, keyID uuid.UUID) error
	DeleteAPIKey(userID, keyID uuid.UUID) error
}

type service struct {
	db *sql.DB
}

var (
	database   = os.Getenv("DB_DATABASE")
	password   = os.Getenv("DB_PASSWORD")
	username   = os.Getenv("DB_USERNAME")
	port       = os.Getenv("DB_PORT")
	host       = os.Getenv("DB_HOST")
	schema     = os.Getenv("DB_SCHEMA")
	dbInstance *service
)

func New() Service {
	// Reuse Connection
	if dbInstance != nil {
		return dbInstance
	}
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable&search_path=%s", username, password, host, port, database, schema)
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		log.Fatal(err)
	}
	dbInstance = &service{
		db: db,
	}
	return dbInstance
}

// Health checks the health of the database connection by pinging the database.
// It returns a map with keys indicating various health statistics.
func (s *service) Health() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	stats := make(map[string]string)

	// Ping the database
	err := s.db.PingContext(ctx)
	if err != nil {
		stats["status"] = "down"
		stats["error"] = fmt.Sprintf("db down: %v", err)
		log.Fatalf("db down: %v", err) // Log the error and terminate the program
		return stats
	}

	// Database is up, add more statistics
	stats["status"] = "up"
	stats["message"] = "It's healthy"

	// Get database stats (like open connections, in use, idle, etc.)
	dbStats := s.db.Stats()
	stats["open_connections"] = strconv.Itoa(dbStats.OpenConnections)
	stats["in_use"] = strconv.Itoa(dbStats.InUse)
	stats["idle"] = strconv.Itoa(dbStats.Idle)
	stats["wait_count"] = strconv.FormatInt(dbStats.WaitCount, 10)
	stats["wait_duration"] = dbStats.WaitDuration.String()
	stats["max_idle_closed"] = strconv.FormatInt(dbStats.MaxIdleClosed, 10)
	stats["max_lifetime_closed"] = strconv.FormatInt(dbStats.MaxLifetimeClosed, 10)

	// Evaluate stats to provide a health message
	if dbStats.OpenConnections > 40 { // Assuming 50 is the max for this example
		stats["message"] = "The database is experiencing heavy load."
	}

	if dbStats.WaitCount > 1000 {
		stats["message"] = "The database has a high number of wait events, indicating potential bottlenecks."
	}

	if dbStats.MaxIdleClosed > int64(dbStats.OpenConnections)/2 {
		stats["message"] = "Many idle connections are being closed, consider revising the connection pool settings."
	}

	if dbStats.MaxLifetimeClosed > int64(dbStats.OpenConnections)/2 {
		stats["message"] = "Many connections are being closed due to max lifetime, consider increasing max lifetime or revising the connection usage pattern."
	}

	return stats
}

// Close closes the database connection.
// It logs a message indicating the disconnection from the specific database.
// If the connection is successfully closed, it returns nil.
// If an error occurs while closing the connection, it returns the error.
func (s *service) Close() error {
	log.Printf("Disconnected from database: %s", database)
	return s.db.Close()
}

// auth queries

func (s *service) CreateUser(email, passwordHash string) (*User, error) {
	var user User
	err := s.db.QueryRow(`
        INSERT INTO users (email, password_hash)
        VALUES ($1, $2)
        RETURNING id, email, password_hash, created_at, updated_at
    `, email, passwordHash).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating user: %w", err)
	}
	return &user, nil
}

func (s *service) GetUserByEmail(email string) (*User, error) {
	var user User
	err := s.db.QueryRow(`
        SELECT id, email, password_hash, created_at, updated_at
        FROM users
        WHERE email = $1
    `, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("error getting user: %w", err)
	}
	return &user, nil
}

func (s *service) GetUserByID(id uuid.UUID) (*User, error) {
	var user User
	err := s.db.QueryRow(`
        SELECT id, email, password_hash, created_at, updated_at
        FROM users
        WHERE id = $1
    `, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("error getting user: %w", err)
	}
	return &user, nil
}

// API Key-related query implementations
func (s *service) CreateAPIKey(userID uuid.UUID, name, keyHash string, expiresAt *time.Time) (*APIKey, error) {
	var apiKey APIKey
	err := s.db.QueryRow(`
        INSERT INTO api_keys (user_id, name, key_hash, expires_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id, user_id, name, key_hash, created_at, last_used_at, expires_at, is_active
    `, userID, name, keyHash, expiresAt).Scan(
		&apiKey.ID,
		&apiKey.UserID,
		&apiKey.Name,
		&apiKey.KeyHash,
		&apiKey.CreatedAt,
		&apiKey.LastUsedAt,
		&apiKey.ExpiresAt,
		&apiKey.IsActive,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating API key: %w", err)
	}
	return &apiKey, nil
}

func (s *service) GetAPIKeyByHash(keyHash string) (*APIKey, error) {
	var apiKey APIKey
	err := s.db.QueryRow(`
        SELECT id, user_id, name, key_hash, created_at, last_used_at, expires_at, is_active
        FROM api_keys
        WHERE key_hash = $1
    `, keyHash).Scan(
		&apiKey.ID,
		&apiKey.UserID,
		&apiKey.Name,
		&apiKey.KeyHash,
		&apiKey.CreatedAt,
		&apiKey.LastUsedAt,
		&apiKey.ExpiresAt,
		&apiKey.IsActive,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("API key not found")
		}
		return nil, fmt.Errorf("error getting API key: %w", err)
	}
	return &apiKey, nil
}

func (s *service) ListAPIKeys(userID uuid.UUID) ([]APIKey, error) {
	rows, err := s.db.Query(`
        SELECT id, user_id, name, key_hash, created_at, last_used_at, expires_at, is_active
        FROM api_keys
        WHERE user_id = $1
        ORDER BY created_at DESC
    `, userID)
	if err != nil {
		return nil, fmt.Errorf("error listing API keys: %w", err)
	}
	defer rows.Close()

	var apiKeys []APIKey
	for rows.Next() {
		var apiKey APIKey
		err := rows.Scan(
			&apiKey.ID,
			&apiKey.UserID,
			&apiKey.Name,
			&apiKey.KeyHash,
			&apiKey.CreatedAt,
			&apiKey.LastUsedAt,
			&apiKey.ExpiresAt,
			&apiKey.IsActive,
		)
		if err != nil {
			return nil, fmt.Errorf("error scanning API key: %w", err)
		}
		apiKeys = append(apiKeys, apiKey)
	}
	return apiKeys, nil
}

func (s *service) UpdateAPIKeyLastUsed(keyID uuid.UUID) error {
	_, err := s.db.Exec(`
        UPDATE api_keys
        SET last_used_at = CURRENT_TIMESTAMP
        WHERE id = $1
    `, keyID)
	if err != nil {
		return fmt.Errorf("error updating API key last used: %w", err)
	}
	return nil
}

func (s *service) RevokeAPIKey(userID, keyID uuid.UUID) error {
	result, err := s.db.Exec(`
        UPDATE api_keys
        SET is_active = false
        WHERE id = $1 AND user_id = $2
    `, keyID, userID)
	if err != nil {
		return fmt.Errorf("error revoking API key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("API key not found or not owned by user")
	}

	return nil
}

func (s *service) DeleteAPIKey(userID, keyID uuid.UUID) error {
	result, err := s.db.Exec(`
		DELETE FROM api_keys
		WHERE id = $1 AND user_id = $2
	`, keyID, userID)
	if err != nil {
		return fmt.Errorf("error deleting API key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("API key not found or not owned by user")
	}

	return nil
}
