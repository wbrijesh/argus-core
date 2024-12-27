package database

import (
	"fmt"
	"strings"
	"time"

	"github.com/gocql/gocql"
	"golang.org/x/exp/rand"
)

func (s *service) BatchInsertLogs(logs []Log) error {
	batch := s.session.NewBatch(gocql.UnloggedBatch)

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
