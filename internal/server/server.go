package server

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	_ "github.com/joho/godotenv/autoload"

	"argus-core/internal/auth"
	"argus-core/internal/database"
)

type Server struct {
	port int

	db   database.Service
	auth auth.Service
}

func NewServer() *http.Server {
	port, _ := strconv.Atoi(os.Getenv("PORT"))

	// Initialize database service
	db := database.New()

	// Initialize auth service
	authService := auth.NewService(db, auth.Config{
		JWTSecret:     os.Getenv("JWT_SECRET"),
		TokenDuration: 24 * time.Hour,
	})

	NewServer := &Server{
		port: port,
		db:   db,
		auth: authService,
	}

	// Declare Server config
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", NewServer.port),
		Handler:      NewServer.RegisterRoutes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return server
}
