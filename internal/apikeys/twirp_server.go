package apikeys

import (
	"context"
	"strings"
	"time"

	"argus-core/internal/auth"
	"argus-core/internal/database"
	pb "argus-core/rpc/apikeys"

	"github.com/gocql/gocql"
	"github.com/twitchtv/twirp"
)

// TwirpServer implements the generated Twirp APIKeysService interface
type TwirpServer struct {
	authService auth.Service
	db          database.Service
}

// NewTwirpServer creates a new Twirp server wrapper around the existing services
func NewTwirpServer(authService auth.Service, db database.Service) pb.APIKeysService {
	return &TwirpServer{authService: authService, db: db}
}

// CreateAPIKey implements the Twirp APIKeysService CreateAPIKey method
func (s *TwirpServer) CreateAPIKey(ctx context.Context, req *pb.CreateAPIKeyRequest) (*pb.CreateAPIKeyResponse, error) {
	userID, err := s.authorize(ctx)
	if err != nil {
		return nil, err
	}

	var expiresAt *time.Time
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			return nil, twirp.NewError(twirp.InvalidArgument, "invalid expiration date format")
		}
		expiresAt = &t
	}

	apiKey, keyString, err := s.authService.CreateAPIKey(userID, req.Name, expiresAt)
	if err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	return &pb.CreateAPIKeyResponse{
		ApiKey: &pb.APIKey{
			Id:         apiKey.ID.String(),
			UserId:     apiKey.UserID.String(),
			Name:       apiKey.Name,
			CreatedAt:  apiKey.CreatedAt.Format(time.RFC3339),
			LastUsedAt: apiKey.LastUsedAt.Format(time.RFC3339),
			ExpiresAt:  apiKey.ExpiresAt.Format(time.RFC3339),
			IsActive:   apiKey.IsActive,
		},
		Key: keyString,
	}, nil
}

// ListAPIKeys implements the Twirp APIKeysService ListAPIKeys method
func (s *TwirpServer) ListAPIKeys(ctx context.Context, req *pb.ListAPIKeysRequest) (*pb.ListAPIKeysResponse, error) {
	userID, err := s.authorize(ctx)
	if err != nil {
		return nil, err
	}

	apiKeys, err := s.authService.ListAPIKeys(userID)
	if err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	var pbAPIKeys []*pb.APIKey
	for _, apiKey := range apiKeys {
		pbAPIKeys = append(pbAPIKeys, &pb.APIKey{
			Id:         apiKey.ID.String(),
			UserId:     apiKey.UserID.String(),
			Name:       apiKey.Name,
			CreatedAt:  apiKey.CreatedAt.Format(time.RFC3339),
			LastUsedAt: apiKey.LastUsedAt.Format(time.RFC3339),
			ExpiresAt:  apiKey.ExpiresAt.Format(time.RFC3339),
			IsActive:   apiKey.IsActive,
		})
	}

	return &pb.ListAPIKeysResponse{ApiKeys: pbAPIKeys}, nil
}

// RevokeAPIKey implements the Twirp APIKeysService RevokeAPIKey method
func (s *TwirpServer) RevokeAPIKey(ctx context.Context, req *pb.RevokeAPIKeyRequest) (*pb.RevokeAPIKeyResponse, error) {
	userID, err := s.authorize(ctx)
	if err != nil {
		return nil, err
	}

	keyID, err := gocql.ParseUUID(req.KeyId)
	if err != nil {
		return nil, twirp.NewError(twirp.InvalidArgument, "invalid key ID")
	}

	err = s.authService.RevokeAPIKey(userID, keyID)
	if err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	return &pb.RevokeAPIKeyResponse{}, nil
}

// DeleteAPIKey implements the Twirp APIKeysService DeleteAPIKey method
func (s *TwirpServer) DeleteAPIKey(ctx context.Context, req *pb.DeleteAPIKeyRequest) (*pb.DeleteAPIKeyResponse, error) {
	userID, err := s.authorize(ctx)
	if err != nil {
		return nil, err
	}

	keyID, err := gocql.ParseUUID(req.KeyId)
	if err != nil {
		return nil, twirp.NewError(twirp.InvalidArgument, "invalid key ID")
	}

	err = s.authService.DeleteAPIKey(userID, keyID)
	if err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	return &pb.DeleteAPIKeyResponse{}, nil
}

// authorize checks the authorization token and returns the user ID
func (s *TwirpServer) authorize(ctx context.Context) (gocql.UUID, error) {
	headers, ok := twirp.HTTPRequestHeaders(ctx)
	if !ok {
		return gocql.UUID{}, twirp.NewError(twirp.Unauthenticated, "missing authorization token")
	}

	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return gocql.UUID{}, twirp.NewError(twirp.Unauthenticated, "missing authorization token")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader {
		return gocql.UUID{}, twirp.NewError(twirp.Unauthenticated, "invalid authorization token format")
	}

	user, err := s.authService.ValidateToken(token)
	if err != nil {
		return gocql.UUID{}, twirp.NewError(twirp.Unauthenticated, "invalid token")
	}

	return user.ID, nil
}
