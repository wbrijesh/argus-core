package applications

import (
	"context"
	"time"

	"argus-core/internal/auth"
	"argus-core/internal/database"
	pb "argus-core/rpc/applications"

	"github.com/gocql/gocql"
	"github.com/twitchtv/twirp"
)

type TwirpServer struct {
	authService auth.Service
	db          database.Service
}

func NewTwirpServer(authService auth.Service, db database.Service) pb.ApplicationsService {
	return &TwirpServer{
		authService: authService,
		db:          db,
	}
}

func formatApplicationResponse(app *database.Application) *pb.Application {
	return &pb.Application{
		Id:          app.ID.String(),
		UserId:      app.UserID.String(),
		Name:        app.Name,
		Description: app.Description,
		CreatedAt:   app.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   app.UpdatedAt.Format(time.RFC3339),
	}
}

func (s *TwirpServer) CreateApplication(ctx context.Context, req *pb.CreateApplicationRequest) (*pb.CreateApplicationResponse, error) {
	if err := validateCreateApplicationRequest(req); err != nil {
		return nil, twirp.InvalidArgumentError("validation_error", err.Error())
	}

	user, err := s.authService.ValidateToken(req.Token)
	if err != nil {
		return nil, twirp.NewError(twirp.Unauthenticated, "invalid token")
	}

	// Generate API key for the application
	apiKey, err := auth.GenerateAPIKey()
	if err != nil {
		return nil, twirp.InternalErrorWith(err)
	}
	keyHash := auth.HashAPIKey(apiKey)

	// Create the application
	app, err := s.db.CreateApplication(user.ID, req.Name, req.Description, keyHash)
	if err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	return &pb.CreateApplicationResponse{
		Application: formatApplicationResponse(app),
		Key:         apiKey,
	}, nil
}

func (s *TwirpServer) ListApplications(ctx context.Context, req *pb.ListApplicationsRequest) (*pb.ListApplicationsResponse, error) {
	user, err := s.authService.ValidateToken(req.Token)
	if err != nil {
		return nil, twirp.NewError(twirp.Unauthenticated, "invalid token")
	}

	apps, err := s.db.ListApplications(user.ID)
	if err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	var pbApps []*pb.Application
	for _, app := range apps {
		pbApps = append(pbApps, formatApplicationResponse(&app))
	}

	return &pb.ListApplicationsResponse{
		Applications: pbApps,
	}, nil
}

func (s *TwirpServer) GetApplication(ctx context.Context, req *pb.GetApplicationRequest) (*pb.GetApplicationResponse, error) {
	user, err := s.authService.ValidateToken(req.Token)
	if err != nil {
		return nil, twirp.NewError(twirp.Unauthenticated, "invalid token")
	}

	appID, err := gocql.ParseUUID(req.ApplicationId)
	if err != nil {
		return nil, twirp.InvalidArgumentError("application_id", "invalid UUID format")
	}

	app, err := s.db.GetApplication(appID)
	if err != nil {
		return nil, twirp.NotFoundError("application not found")
	}

	if app.UserID != user.ID {
		return nil, twirp.NewError(twirp.PermissionDenied, "not authorized to access this application")
	}

	return &pb.GetApplicationResponse{
		Application: formatApplicationResponse(app),
	}, nil
}

func (s *TwirpServer) UpdateApplication(ctx context.Context, req *pb.UpdateApplicationRequest) (*pb.UpdateApplicationResponse, error) {
	if err := validateUpdateApplicationRequest(req); err != nil {
		return nil, twirp.InvalidArgumentError("validation_error", err.Error())
	}

	user, err := s.authService.ValidateToken(req.Token)
	if err != nil {
		return nil, twirp.NewError(twirp.Unauthenticated, "invalid token")
	}

	appID, err := gocql.ParseUUID(req.ApplicationId)
	if err != nil {
		return nil, twirp.InvalidArgumentError("application_id", "invalid UUID format")
	}

	// Verify ownership
	currentApp, err := s.db.GetApplication(appID)
	if err != nil {
		return nil, twirp.NotFoundError("application not found")
	}

	if currentApp.UserID != user.ID {
		return nil, twirp.NewError(twirp.PermissionDenied, "not authorized to modify this application")
	}

	// Update the application
	updatedApp, err := s.db.UpdateApplication(appID, req.Name, req.Description)
	if err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	return &pb.UpdateApplicationResponse{
		Application: formatApplicationResponse(updatedApp),
	}, nil
}

func (s *TwirpServer) DeleteApplication(ctx context.Context, req *pb.DeleteApplicationRequest) (*pb.DeleteApplicationResponse, error) {
	user, err := s.authService.ValidateToken(req.Token)
	if err != nil {
		return nil, twirp.NewError(twirp.Unauthenticated, "invalid token")
	}

	appID, err := gocql.ParseUUID(req.ApplicationId)
	if err != nil {
		return nil, twirp.InvalidArgumentError("application_id", "invalid UUID format")
	}

	// Verify ownership
	app, err := s.db.GetApplication(appID)
	if err != nil {
		return nil, twirp.NotFoundError("application not found")
	}

	if app.UserID != user.ID {
		return nil, twirp.NewError(twirp.PermissionDenied, "not authorized to delete this application")
	}

	// Delete the application
	if err := s.db.DeleteApplication(appID); err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	return &pb.DeleteApplicationResponse{}, nil
}

func (s *TwirpServer) RegenerateKey(ctx context.Context, req *pb.RegenerateKeyRequest) (*pb.RegenerateKeyResponse, error) {
	user, err := s.authService.ValidateToken(req.Token)
	if err != nil {
		return nil, twirp.NewError(twirp.Unauthenticated, "invalid token")
	}

	appID, err := gocql.ParseUUID(req.ApplicationId)
	if err != nil {
		return nil, twirp.InvalidArgumentError("application_id", "invalid UUID format")
	}

	// Verify ownership
	app, err := s.db.GetApplication(appID)
	if err != nil {
		return nil, twirp.NotFoundError("application not found")
	}

	if app.UserID != user.ID {
		return nil, twirp.NewError(twirp.PermissionDenied, "not authorized to modify this application")
	}

	// Generate new API key
	newKey, err := auth.GenerateAPIKey()
	if err != nil {
		return nil, twirp.InternalErrorWith(err)
	}
	keyHash := auth.HashAPIKey(newKey)

	// Update the application with new key hash
	if err := s.db.RegenerateApplicationKey(appID, keyHash); err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	return &pb.RegenerateKeyResponse{
		Key: newKey,
	}, nil
}
