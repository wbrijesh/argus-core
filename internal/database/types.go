package database

import (
	"time"

	"github.com/gocql/gocql"
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
