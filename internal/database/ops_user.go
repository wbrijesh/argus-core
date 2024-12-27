package database

import (
	"fmt"
	"time"

	"github.com/gocql/gocql"
)

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
