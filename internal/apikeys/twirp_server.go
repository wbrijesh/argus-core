package apikeys

import (
	"context"
	"time"

	"argus-core/internal/auth"
	"argus-core/internal/database"
	pb "argus-core/rpc/apikeys"

	"github.com/gocql/gocql"
	"github.com/twitchtv/twirp"
)

// TwirpServer implements the APIKeysService for managing API keys
type TwirpServer struct {
	authService auth.Service
	db          database.Service
}

// NewTwirpServer creates a new Twirp server wrapper around the existing services
func NewTwirpServer(authService auth.Service, db database.Service) pb.APIKeysService {
	return &TwirpServer{authService: authService, db: db}
}

// formatAPIKeyResponse converts a database API key to a protobuf API key
func formatAPIKeyResponse(apiKey *database.APIKey) *pb.APIKey {
	response := &pb.APIKey{
		Id:        apiKey.ID.String(),
		UserId:    apiKey.UserID.String(),
		Name:      apiKey.Name,
		CreatedAt: apiKey.CreatedAt.Format(time.RFC3339),
		IsActive:  apiKey.IsActive,
	}

	if apiKey.LastUsedAt != nil {
		response.LastUsedAt = apiKey.LastUsedAt.Format(time.RFC3339)
	}

	if apiKey.ExpiresAt != nil {
		response.ExpiresAt = apiKey.ExpiresAt.Format(time.RFC3339)
	}

	return response
}

// CreateAPIKey implements the Twirp APIKeysService CreateAPIKey method
func (s *TwirpServer) CreateAPIKey(ctx context.Context, req *pb.CreateAPIKeyRequest) (*pb.CreateAPIKeyResponse, error) {
	if req.Token == "" {
		return nil, twirp.NewError(twirp.Unauthenticated, "token is required")
	}
	if req.Name == "" {
		return nil, twirp.NewError(twirp.InvalidArgument, "name is required")
	}

	// Validate token and get user
	user, err := s.authService.ValidateToken(req.Token)
	if err != nil {
		return nil, twirp.NewError(twirp.Unauthenticated, "invalid token")
	}

	// Parse expiration date if provided
	var expiresAt *time.Time
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			return nil, twirp.NewError(twirp.InvalidArgument, "expires_at must be in RFC3339 format")
		}
		if t.Before(time.Now()) {
			return nil, twirp.NewError(twirp.InvalidArgument, "expiration date cannot be in the past")
		}
		expiresAt = &t
	}

	// Create API key
	apiKey, keyString, err := s.authService.CreateAPIKey(user.ID, req.Name, expiresAt)
	if err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	return &pb.CreateAPIKeyResponse{
		ApiKey: formatAPIKeyResponse(apiKey),
		Key:    keyString,
	}, nil
}

// ListAPIKeys implements the Twirp APIKeysService ListAPIKeys method
func (s *TwirpServer) ListAPIKeys(ctx context.Context, req *pb.ListAPIKeysRequest) (*pb.ListAPIKeysResponse, error) {
	if req.Token == "" {
		return nil, twirp.NewError(twirp.Unauthenticated, "token is required")
	}

	// Validate token and get user
	user, err := s.authService.ValidateToken(req.Token)
	if err != nil {
		return nil, twirp.NewError(twirp.Unauthenticated, "invalid token")
	}

	apiKeys, err := s.authService.ListAPIKeys(user.ID)
	if err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	var pbAPIKeys []*pb.APIKey
	for _, apiKey := range apiKeys {
		pbAPIKeys = append(pbAPIKeys, formatAPIKeyResponse(&apiKey))
	}

	return &pb.ListAPIKeysResponse{ApiKeys: pbAPIKeys}, nil
}

// RevokeAPIKey implements the Twirp APIKeysService RevokeAPIKey method
func (s *TwirpServer) RevokeAPIKey(ctx context.Context, req *pb.RevokeAPIKeyRequest) (*pb.RevokeAPIKeyResponse, error) {
	if req.Token == "" {
		return nil, twirp.NewError(twirp.Unauthenticated, "token is required")
	}
	if req.KeyId == "" {
		return nil, twirp.NewError(twirp.InvalidArgument, "key_id is required")
	}

	// Validate token and get user
	user, err := s.authService.ValidateToken(req.Token)
	if err != nil {
		return nil, twirp.NewError(twirp.Unauthenticated, "invalid token")
	}

	keyID, err := gocql.ParseUUID(req.KeyId)
	if err != nil {
		return nil, twirp.NewError(twirp.InvalidArgument, "invalid key ID format")
	}

	err = s.authService.RevokeAPIKey(user.ID, keyID)
	if err != nil {
		if err == ErrAPIKeyInvalid {
			return nil, twirp.NewError(twirp.NotFound, "API key not found")
		}
		return nil, twirp.InternalErrorWith(err)
	}

	return &pb.RevokeAPIKeyResponse{}, nil
}

// DeleteAPIKey implements the Twirp APIKeysService DeleteAPIKey method
func (s *TwirpServer) DeleteAPIKey(ctx context.Context, req *pb.DeleteAPIKeyRequest) (*pb.DeleteAPIKeyResponse, error) {
	if req.Token == "" {
		return nil, twirp.NewError(twirp.Unauthenticated, "token is required")
	}
	if req.KeyId == "" {
		return nil, twirp.NewError(twirp.InvalidArgument, "key_id is required")
	}

	// Validate token and get user
	user, err := s.authService.ValidateToken(req.Token)
	if err != nil {
		return nil, twirp.NewError(twirp.Unauthenticated, "invalid token")
	}

	keyID, err := gocql.ParseUUID(req.KeyId)
	if err != nil {
		return nil, twirp.NewError(twirp.InvalidArgument, "invalid key ID format")
	}

	err = s.authService.DeleteAPIKey(user.ID, keyID)
	if err != nil {
		if err == ErrAPIKeyInvalid {
			return nil, twirp.NewError(twirp.NotFound, "API key not found")
		}
		return nil, twirp.InternalErrorWith(err)
	}

	return &pb.DeleteAPIKeyResponse{}, nil
}
