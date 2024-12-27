package database

import (
	"fmt"
	"time"

	"github.com/gocql/gocql"
)

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
	// First, delete all logs associated with the application
	if err := s.session.Query(`
        DELETE FROM logs WHERE application_id = ?`,
		id,
	).Exec(); err != nil {
		return fmt.Errorf("error deleting application logs: %w", err)
	}

	// Then delete the application itself
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
