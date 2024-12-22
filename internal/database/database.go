package database

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gocql/gocql"
	_ "github.com/joho/godotenv/autoload"
	"golang.org/x/exp/rand"
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

type Log struct {
	ApplicationID gocql.UUID `json:"application_id"`
	LogID         gocql.UUID `json:"log_id"`
	UserID        gocql.UUID `json:"user_id"`
	Timestamp     time.Time  `json:"timestamp"`
	Level         string     `json:"level"`
	Message       string     `json:"message"`
}

type LogsFilter struct {
	ApplicationID gocql.UUID
	PageSize      int
	Cursor        *time.Time
	LogLevel      string
	StartTime     *time.Time
	EndTime       *time.Time
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

	BatchInsertLogs(logs []Log) error
	GetRecentLogs(filter LogsFilter) ([]Log, error)
	ValidateApplicationKey(keyHash string) (*Application, error) // Helper method for API key validation
	GenerateDummyLogs(applicationID gocql.UUID) (int, error)
}

type service struct {
	session *gocql.Session
}

func New() Service {
	// Load environment variables
	cassandraHost := os.Getenv("CASSANDRA_HOST")
	cassandraUsername := os.Getenv("CASSANDRA_USERNAME")
	cassandraPassword := os.Getenv("CASSANDRA_PASSWORD")
	cassandraKeyspace := os.Getenv("CASSANDRA_KEYSPACE")

	// Download certificate
	resp, err := http.Get("https://certs.secureserver.net/repository/sf-class2-root.crt")
	if err != nil {
		log.Fatal("Failed to download certificate:", err)
	}
	defer resp.Body.Close()

	tempCertFile, err := os.CreateTemp("", "cassandra-cert-*.crt")
	if err != nil {
		log.Fatal("Failed to create temp cert file:", err)
	}
	defer os.Remove(tempCertFile.Name())

	if _, err := io.Copy(tempCertFile, resp.Body); err != nil {
		log.Fatal("Failed to write certificate to file:", err)
	}

	cluster := gocql.NewCluster(cassandraHost)
	cluster.Port = 9142
	cluster.Authenticator = gocql.PasswordAuthenticator{
		Username: cassandraUsername,
		Password: cassandraPassword,
	}
	cluster.SslOpts = &gocql.SslOptions{
		CaPath:                 tempCertFile.Name(),
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

// BatchInsertLogs inserts multiple logs in a batch operation
func (s *service) BatchInsertLogs(logs []Log) error {
	batch := s.session.NewBatch(gocql.LoggedBatch)

	for _, log := range logs {
		batch.Query(`
            INSERT INTO logs (
                application_id,
                timestamp,
                log_id,
                user_id,
                log_level,
                message
            ) VALUES (?, ?, ?, ?, ?, ?)`,
			log.ApplicationID,
			log.Timestamp,
			log.LogID,
			log.UserID,
			log.Level,
			log.Message,
		)
	}

	if err := s.session.ExecuteBatch(batch); err != nil {
		return fmt.Errorf("failed to batch insert logs: %w", err)
	}

	return nil
}

func (s *service) GetRecentLogs(filter LogsFilter) ([]Log, error) {
	if filter.PageSize <= 0 || filter.PageSize > 100 {
		filter.PageSize = 100
	}

	// Build the query dynamically based on filters
	query := "SELECT application_id, timestamp, log_id, user_id, log_level, message FROM logs WHERE application_id = ?"
	args := []interface{}{filter.ApplicationID}

	// Add timestamp conditions
	if filter.Cursor != nil {
		query += " AND timestamp < ?"
		args = append(args, *filter.Cursor)
	}
	if filter.StartTime != nil {
		query += " AND timestamp >= ?"
		args = append(args, *filter.StartTime)
	}
	if filter.EndTime != nil {
		query += " AND timestamp <= ?"
		args = append(args, *filter.EndTime)
	}

	// Add log level filter if specified
	if filter.LogLevel != "" {
		query += " AND log_level = ?"
		args = append(args, filter.LogLevel)
	}

	// Add ordering and limit
	query += " ORDER BY timestamp DESC LIMIT ?"
	args = append(args, filter.PageSize)

	// Execute query with ALLOW FILTERING
	iter := s.session.Query(query+" ALLOW FILTERING", args...).Iter()

	var logs []Log
	var log Log
	for iter.Scan(
		&log.ApplicationID,
		&log.Timestamp,
		&log.LogID,
		&log.UserID,
		&log.Level,
		&log.Message,
	) {
		logs = append(logs, log)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("error fetching logs: %w", err)
	}

	return logs, nil
}

// ValidateApplicationKey validates an API key and returns the associated application
func (s *service) ValidateApplicationKey(keyHash string) (*Application, error) {
	var app Application

	// Query the applications table using the key hash
	if err := s.session.Query(`
        SELECT id, user_id, name, description, key_hash, created_at, updated_at
        FROM applications
        WHERE key_hash = ?
        ALLOW FILTERING`,
		keyHash,
	).Scan(
		&app.ID,
		&app.UserID,
		&app.Name,
		&app.Description,
		&app.KeyHash,
		&app.CreatedAt,
		&app.UpdatedAt,
	); err != nil {
		if err == gocql.ErrNotFound {
			return nil, fmt.Errorf("invalid API key")
		}
		return nil, fmt.Errorf("error validating API key: %w", err)
	}

	return &app, nil
}

func (s *service) GenerateDummyLogs(applicationID gocql.UUID) (int, error) {
	// Get the application to ensure it exists and get its user ID
	var app Application
	if err := s.session.Query(`
								SELECT id, user_id FROM applications WHERE id = ?
				`, applicationID).Scan(&app.ID, &app.UserID); err != nil {
		return 0, fmt.Errorf("application not found: %w", err)
	}

	// Generate 30 logs spanning the last 5 minutes
	now := time.Now()
	startTime := now.Add(-5 * time.Minute)

	batch := s.session.NewBatch(gocql.UnloggedBatch)

	// Sample messages and levels for variety
	messages := []string{
		"User authentication successful",
		"Database connection established",
		"API request processed successfully",
		"Cache miss for key: %s",
		"Background job completed in %dms",
		"Memory usage: %d MB",
		"Request failed with status code: %d",
		"Rate limit exceeded for IP: %s",
		"Configuration reload initiated",
		"File upload completed: %s",
	}

	levelWeights := map[string]int{
		"DEBUG": 15,
		"INFO":  60,
		"WARN":  15,
		"ERROR": 8,
		"FATAL": 2,
	}

	// Random data for interpolation
	sampleIPs := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8"}
	sampleFiles := []string{"user.jpg", "data.csv", "config.json", "backup.zip"}
	sampleKeys := []string{"user:1234", "session:5678", "settings:9012", "temp:3456"}

	for i := 0; i < 30; i++ {
		// Calculate timestamp with even distribution over 5 minutes
		progress := float64(i) / 30.0
		timestamp := startTime.Add(time.Duration(progress * 5 * float64(time.Minute)))

		// Select log level based on weights
		rand.Seed(uint64(time.Now().UnixNano()))
		r := rand.Intn(100)
		var level string
		sum := 0
		for l, weight := range levelWeights {
			sum += weight
			if r < sum {
				level = l
				break
			}
		}

		// Select and format message
		msgTemplate := messages[rand.Intn(len(messages))]
		var msg string

		switch {
		case strings.Contains(msgTemplate, "IP:"):
			msg = fmt.Sprintf(msgTemplate, sampleIPs[rand.Intn(len(sampleIPs))])
		case strings.Contains(msgTemplate, "File"):
			msg = fmt.Sprintf(msgTemplate, sampleFiles[rand.Intn(len(sampleFiles))])
		case strings.Contains(msgTemplate, "key:"):
			msg = fmt.Sprintf(msgTemplate, sampleKeys[rand.Intn(len(sampleKeys))])
		case strings.Contains(msgTemplate, "MB"):
			msg = fmt.Sprintf(msgTemplate, rand.Intn(1000))
		case strings.Contains(msgTemplate, "ms"):
			msg = fmt.Sprintf(msgTemplate, rand.Intn(500))
		case strings.Contains(msgTemplate, "status code:"):
			codes := []int{400, 401, 403, 404, 500, 502, 503}
			msg = fmt.Sprintf(msgTemplate, codes[rand.Intn(len(codes))])
		default:
			msg = msgTemplate
		}

		// Add to batch
		batch.Query(`
												INSERT INTO logs (
																application_id,
																timestamp,
																log_id,
																user_id,
																log_level,
																message
												) VALUES (?, ?, ?, ?, ?, ?)`,
			applicationID,
			timestamp,
			gocql.TimeUUID(),
			app.UserID,
			level,
			msg,
		)
	}

	if err := s.session.ExecuteBatch(batch); err != nil {
		return 0, fmt.Errorf("failed to insert dummy logs: %w", err)
	}

	return 30, nil
}
