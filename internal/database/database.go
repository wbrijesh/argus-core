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

type Application struct {
	ID          gocql.UUID `json:"id"`
	UserID      gocql.UUID `json:"user_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	KeyHash     string     `json:"-"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type Service interface {
	Health() map[string]string
	Close() error

	CreateUser(email, passwordHash string) (*User, error)
	GetUserByEmail(email string) (*User, error)
	GetUserByID(id gocql.UUID) (*User, error)

	CreateApplication(userID gocql.UUID, name, description, keyHash string) (*Application, error)
	GetApplication(id gocql.UUID) (*Application, error)
	ListApplications(userID gocql.UUID) ([]Application, error)
	UpdateApplication(id gocql.UUID, name, description string) (*Application, error)
	DeleteApplication(id gocql.UUID) error
	RegenerateApplicationKey(appID gocql.UUID, newKeyHash string) error
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

func (s *service) CreateApplication(userID gocql.UUID, name, description, keyHash string) (*Application, error) {
	app := &Application{
		ID:          gocql.TimeUUID(),
		UserID:      userID,
		Name:        name,
		Description: description,
		KeyHash:     keyHash,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.session.Query(`
								INSERT INTO applications (id, user_id, name, description, key_hash, created_at, updated_at)
								VALUES (?, ?, ?, ?, ?, ?, ?)`,
		app.ID, app.UserID, app.Name, app.Description, app.KeyHash, app.CreatedAt, app.UpdatedAt,
	).Exec(); err != nil {
		return nil, fmt.Errorf("error creating application: %w", err)
	}

	return app, nil
}

func (s *service) GetApplication(id gocql.UUID) (*Application, error) {
	var app Application
	if err := s.session.Query(`
								SELECT id, user_id, name, description, key_hash, created_at, updated_at
								FROM applications WHERE id = ?`,
		id,
	).Scan(
		&app.ID, &app.UserID, &app.Name, &app.Description,
		&app.KeyHash, &app.CreatedAt, &app.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("application not found: %w", err)
	}
	return &app, nil
}

func (s *service) ListApplications(userID gocql.UUID) ([]Application, error) {
	iter := s.session.Query(`
								SELECT id, user_id, name, description, key_hash, created_at, updated_at
								FROM applications WHERE user_id = ? ALLOW FILTERING`,
		userID,
	).Iter()

	var apps []Application
	var app Application
	for iter.Scan(
		&app.ID, &app.UserID, &app.Name, &app.Description,
		&app.KeyHash, &app.CreatedAt, &app.UpdatedAt,
	) {
		apps = append(apps, app)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("error listing applications: %w", err)
	}

	return apps, nil
}

func (s *service) UpdateApplication(id gocql.UUID, name, description string) (*Application, error) {
	now := time.Now()
	if err := s.session.Query(`
        UPDATE applications
        SET name = ?,
            description = ?,
            updated_at = ?
        WHERE id = ?`,
		name, description, now, id,
	).Exec(); err != nil {
		return nil, fmt.Errorf("error updating application: %w", err)
	}

	return s.GetApplication(id)
}

func (s *service) DeleteApplication(id gocql.UUID) error {
	if err := s.session.Query(`
								DELETE FROM applications WHERE id = ?`,
		id,
	).Exec(); err != nil {
		return fmt.Errorf("error deleting application: %w", err)
	}

	return nil
}

func (s *service) RegenerateApplicationKey(appID gocql.UUID, newKeyHash string) error {
	now := time.Now()
	if err := s.session.Query(`
        UPDATE applications
        SET key_hash = ?,
            updated_at = ?
        WHERE id = ?`,
		newKeyHash, now, appID,
	).Exec(); err != nil {
		return fmt.Errorf("error regenerating application key: %w", err)
	}
	return nil
}
