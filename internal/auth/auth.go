package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/gocql/gocql"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"argus-core/internal/database"
)

// Request types
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type CreateAPIKeyRequest struct {
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidToken       = errors.New("invalid token")
	ErrAPIKeyNotFound     = errors.New("API key not found")
)

type Service interface {
	Register(email, password string) (*database.User, error)
	Login(email, password string) (string, *database.User, error) // Returns JWT token and user
	ValidateToken(token string) (*database.User, error)

	CreateAPIKey(userID gocql.UUID, name string, expiresAt *time.Time) (*database.APIKey, string, error) // Returns APIKey and the actual key
	ValidateAPIKey(key string) (*database.APIKey, error)
	ListAPIKeys(userID gocql.UUID) ([]database.APIKey, error)
	RevokeAPIKey(userID, keyID gocql.UUID) error
	DeleteAPIKey(userID, keyID gocql.UUID) error
}

type service struct {
	db            database.Service
	jwtSecret     []byte
	tokenDuration time.Duration
}

type Config struct {
	JWTSecret     string
	TokenDuration time.Duration
}

func NewService(db database.Service, config Config) Service {
	return &service{
		db:            db,
		jwtSecret:     []byte(config.JWTSecret),
		tokenDuration: config.TokenDuration,
	}
}

func (s *service) Register(email, password string) (*database.User, error) {
	// Check if user already exists
	existingUser, err := s.db.GetUserByEmail(email)
	if err == nil && existingUser != nil {
		return nil, ErrUserExists
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create user
	user, err := s.db.CreateUser(email, string(hashedPassword))
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *service) Login(email, password string) (string, *database.User, error) {
	// Get user
	user, err := s.db.GetUserByEmail(email)
	if err != nil {
		return "", nil, ErrInvalidCredentials
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", nil, ErrInvalidCredentials
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID.String(),
		"exp": time.Now().Add(s.tokenDuration).Unix(),
	})

	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", nil, err
	}

	return tokenString, user, nil
}

func (s *service) ValidateToken(tokenString string) (*database.User, error) {
	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return s.jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	// Parse user ID
	userID, err := gocql.ParseUUID(claims["sub"].(string))
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Get user from database
	user, err := s.db.GetUserByID(userID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *service) CreateAPIKey(userID gocql.UUID, name string, expiresAt *time.Time) (*database.APIKey, string, error) {
	// Generate random API key
	apiKeyStr, err := generateAPIKey()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate API key: %w", err)
	}

	// Hash the API key
	keyHash := hashAPIKey(apiKeyStr)

	// Create API key in database
	apiKey, err := s.db.CreateAPIKey(userID, name, keyHash, expiresAt)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create API key: %w", err)
	}

	return apiKey, apiKeyStr, nil
}

func (s *service) ValidateAPIKey(key string) (*database.APIKey, error) {
	// Validate key format
	if !validateAPIKeyFormat(key) {
		return nil, ErrAPIKeyNotFound
	}

	keyHash := hashAPIKey(key)

	apiKey, err := s.db.GetAPIKeyByHash(keyHash)
	if err != nil {
		return nil, ErrAPIKeyNotFound
	}

	// Check if key is expired
	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return nil, ErrAPIKeyNotFound
	}

	// Check if key is active
	if !apiKey.IsActive {
		return nil, ErrAPIKeyNotFound
	}

	return apiKey, nil
}

func (s *service) ListAPIKeys(userID gocql.UUID) ([]database.APIKey, error) {
	return s.db.ListAPIKeys(userID)
}

func (s *service) RevokeAPIKey(userID, keyID gocql.UUID) error {
	return s.db.RevokeAPIKey(userID, keyID)
}

func (s *service) DeleteAPIKey(userID, keyID gocql.UUID) error {
	return s.db.DeleteAPIKey(userID, keyID)
}
