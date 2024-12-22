package server

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	_ "github.com/joho/godotenv/autoload"

	"argus-core/internal/database"

	"argus-core/internal/applications"
	"argus-core/internal/auth"
	"argus-core/internal/logs"

	applicationspb "argus-core/rpc/applications"
	authpb "argus-core/rpc/auth"
	logspb "argus-core/rpc/logs"
)

type Server struct {
	port int
	db   database.Service
	auth auth.Service
}

// CORSMiddleware wraps a handler with CORS support
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*") // In production, replace * with your frontend domain
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
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

	// Create Twirp Server handlers
	authHandler := authpb.NewAuthServiceServer(auth.NewTwirpServer(authService))
	applicationsHandler := applicationspb.NewApplicationsServiceServer(applications.NewTwirpServer(authService, db))
	logsHandler := logspb.NewLogsServiceServer(logs.NewTwirpServer(db, authService))

	// Combine handlers
	mux := http.NewServeMux()
	mux.Handle(authHandler.PathPrefix(), authHandler)
	mux.Handle(applicationsHandler.PathPrefix(), applicationsHandler)
	mux.Handle(logsHandler.PathPrefix(), logsHandler)

	// Wrap the mux with CORS middleware
	handler := CORSMiddleware(mux)

	// Declare Server config
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      handler,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return server
}
