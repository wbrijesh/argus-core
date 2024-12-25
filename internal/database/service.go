package database

import "github.com/gocql/gocql"

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
