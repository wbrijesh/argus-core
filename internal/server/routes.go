package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/gocql/gocql"

	"argus-core/internal/auth"
)

func (s *Server) RegisterRoutes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Get("/", s.HelloWorldHandler)
	r.Get("/health", s.healthHandler)

	// Auth routes
	r.Post("/auth/register", s.handleRegister)
	r.Post("/auth/login", s.handleLogin)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(s.authMiddleware)
		r.Get("/auth/me", s.handleGetCurrentUser)
		r.Post("/api-keys", s.handleCreateAPIKey)
		r.Get("/api-keys", s.handleListAPIKeys)
		r.Delete("/api-keys/{keyID}", s.handleDeleteAPIKey)
		r.Post("/api-keys/{keyID}/revoke", s.handleRevokeAPIKey)
	})

	return r
}

func (s *Server) HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	resp := make(map[string]string)
	resp["message"] = "Hello World"

	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("error handling JSON marshal. Err: %v", err)
	}

	_, _ = w.Write(jsonResp)
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	jsonResp, _ := json.Marshal(s.db.Health())
	_, _ = w.Write(jsonResp)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req auth.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	user, err := s.auth.Register(req.Email, req.Password)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to register user")
		return
	}

	s.respondWithJSON(w, http.StatusCreated, user)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req auth.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	token, user, err := s.auth.Login(req.Email, req.Password)
	if err != nil {
		s.respondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	s.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"token": token,
		"user":  user,
	})
}

func (s *Server) handleGetCurrentUser(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by authMiddleware)
	userID := r.Context().Value("userID").(gocql.UUID)

	user, err := s.db.GetUserByID(userID)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to get user details")
		return
	}

	s.respondWithJSON(w, http.StatusOK, user)
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req auth.CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	userID := r.Context().Value("userID").(gocql.UUID)
	apiKey, keyString, err := s.auth.CreateAPIKey(userID, req.Name, req.ExpiresAt)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to create API key")
		return
	}

	s.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"api_key": apiKey,
		"key":     keyString,
	})
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(gocql.UUID)
	apiKeys, err := s.auth.ListAPIKeys(userID)
	if err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to list API keys")
		return
	}

	s.respondWithJSON(w, http.StatusOK, apiKeys)
}

func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(gocql.UUID)
	keyID, err := gocql.ParseUUID(chi.URLParam(r, "keyID"))
	if err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid key ID")
		return
	}

	if err := s.auth.RevokeAPIKey(userID, keyID); err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to revoke API key")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(gocql.UUID)
	keyID, err := gocql.ParseUUID(chi.URLParam(r, "keyID"))
	if err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid key ID")
		return
	}

	if err := s.auth.DeleteAPIKey(userID, keyID); err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to delete API key")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.respondWithError(w, http.StatusUnauthorized, "No authorization header")
			return
		}

		user, err := s.auth.ValidateToken(authHeader)
		if err != nil {
			s.respondWithError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		// Add user ID to context
		ctx := context.WithValue(r.Context(), "userID", user.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) respondWithError(w http.ResponseWriter, code int, message string) {
	s.respondWithJSON(w, code, map[string]string{"error": message})
}

func (s *Server) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Failed to marshal JSON response"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
