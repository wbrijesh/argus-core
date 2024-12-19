package auth

import (
	"context"
	"time"

	pb "argus-core/rpc/auth"

	"github.com/golang-jwt/jwt/v5"
	"github.com/twitchtv/twirp"
)

// TwirpServer implements the generated Twirp AuthService interface
type TwirpServer struct {
	auth Service // existing auth service
}

// NewTwirpServer creates a new Twirp server wrapper around the existing auth service
func NewTwirpServer(auth Service) pb.AuthService {
	return &TwirpServer{auth: auth}
}

// Register implements the Twirp AuthService Register method
func (s *TwirpServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, twirp.NewError(twirp.InvalidArgument, "email and password are required")
	}

	user, err := s.auth.Register(req.Email, req.Password)
	if err != nil {
		if err == ErrUserExists {
			return nil, twirp.NewError(twirp.AlreadyExists, "user already exists")
		}
		return nil, twirp.InternalErrorWith(err)
	}

	return &pb.RegisterResponse{
		User: &pb.User{
			Id:        user.ID.String(),
			Email:     user.Email,
			CreatedAt: user.CreatedAt.Format(time.RFC3339),
			UpdatedAt: user.UpdatedAt.Format(time.RFC3339),
		},
	}, nil
}

// Login implements the Twirp AuthService Login method
func (s *TwirpServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, twirp.NewError(twirp.InvalidArgument, "email and password are required")
	}

	token, user, err := s.auth.Login(req.Email, req.Password)
	if err != nil {
		if err == ErrInvalidCredentials {
			return nil, twirp.NewError(twirp.Unauthenticated, "invalid credentials")
		}
		return nil, twirp.InternalErrorWith(err)
	}

	return &pb.LoginResponse{
		Token: token,
		User: &pb.User{
			Id:        user.ID.String(),
			Email:     user.Email,
			CreatedAt: user.CreatedAt.Format(time.RFC3339),
			UpdatedAt: user.UpdatedAt.Format(time.RFC3339),
		},
	}, nil
}

// ValidateToken implements the Twirp AuthService ValidateToken method
func (s *TwirpServer) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	if req.Token == "" {
		return nil, twirp.NewError(twirp.InvalidArgument, "token is required")
	}

	// Parse token to check expiration first
	token, err := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, twirp.NewError(twirp.Unauthenticated, "invalid token signing method")
		}
		return s.auth.(*service).jwtSecret, nil // Note: This requires the secret to be accessible
	})

	if err != nil {
		if err.Error() == "Token is expired" {
			return nil, twirp.NewError(twirp.Unauthenticated, "token has expired")
		}
		return nil, twirp.NewError(twirp.Unauthenticated, "invalid token")
	}

	if !token.Valid {
		return nil, twirp.NewError(twirp.Unauthenticated, "invalid token")
	}

	// Now use the service's ValidateToken which will get the user
	user, err := s.auth.ValidateToken(req.Token)
	if err != nil {
		if err == ErrInvalidToken {
			return nil, twirp.NewError(twirp.Unauthenticated, "invalid token")
		}
		return nil, twirp.InternalErrorWith(err)
	}

	return &pb.ValidateTokenResponse{
		User: &pb.User{
			Id:        user.ID.String(),
			Email:     user.Email,
			CreatedAt: user.CreatedAt.Format(time.RFC3339),
			UpdatedAt: user.UpdatedAt.Format(time.RFC3339),
		},
	}, nil
}
