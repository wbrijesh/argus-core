package logs

import (
	"context"
	"time"

	"github.com/gocql/gocql"
	"github.com/twitchtv/twirp"

	"argus-core/internal/auth"
	"argus-core/internal/database"
	pb "argus-core/rpc/logs"
)

type TwirpServer struct {
	db          database.Service
	authService auth.Service
}

func NewTwirpServer(db database.Service, authService auth.Service) pb.LogsService {
	return &TwirpServer{
		db:          db,
		authService: authService,
	}
}

func (s *TwirpServer) SendLogs(ctx context.Context, req *pb.SendLogsRequest) (*pb.SendLogsResponse, error) {
	if err := validateSendLogsRequest(req); err != nil {
		return nil, twirp.InvalidArgumentError("validation_error", err.Error())
	}

	// Validate API key and get application
	keyHash := auth.HashAPIKey(req.ApiKey)
	app, err := s.db.ValidateApplicationKey(keyHash)
	if err != nil {
		return nil, twirp.NewError(twirp.Unauthenticated, "invalid API key")
	}

	// Convert logs to database format
	dbLogs := make([]database.Log, 0, len(req.Logs))
	for _, log := range req.Logs {
		timestamp := time.Now()
		if log.Timestamp != "" {
			if ts, err := time.Parse(time.RFC3339, log.Timestamp); err == nil {
				timestamp = ts
			}
		}

		dbLogs = append(dbLogs, database.Log{
			ApplicationID: app.ID,
			LogID:         gocql.TimeUUID(),
			UserID:        app.UserID,
			Timestamp:     timestamp,
			Level:         log.Level.String(),
			Message:       log.Message,
		})
	}

	// Insert logs
	if err := s.db.BatchInsertLogs(dbLogs); err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	return &pb.SendLogsResponse{
		AcceptedCount: int32(len(dbLogs)),
	}, nil
}

func (s *TwirpServer) GetLogs(ctx context.Context, req *pb.GetLogsRequest) (*pb.GetLogsResponse, error) {
	// Validate token
	user, err := s.authService.ValidateToken(req.Token)
	if err != nil {
		return nil, twirp.NewError(twirp.Unauthenticated, "invalid token")
	}

	// Parse application ID
	appID, err := gocql.ParseUUID(req.ApplicationId)
	if err != nil {
		return nil, twirp.InvalidArgumentError("application_id", "invalid UUID format")
	}

	// Verify application ownership
	app, err := s.db.GetApplication(appID)
	if err != nil {
		return nil, twirp.NotFoundError("application not found")
	}
	if app.UserID != user.ID {
		return nil, twirp.NewError(twirp.PermissionDenied, "not authorized to access this application")
	}

	// Parse cursor if provided
	var cursor *time.Time
	if req.Cursor != "" {
		t, err := time.Parse(time.RFC3339, req.Cursor)
		if err != nil {
			return nil, twirp.InvalidArgumentError("cursor", "invalid timestamp format")
		}
		cursor = &t
	}

	// Parse optional timestamps
	var startTime, endTime *time.Time
	if req.StartTime != "" {
		t, err := time.Parse(time.RFC3339, req.StartTime)
		if err != nil {
			return nil, twirp.InvalidArgumentError("start_time", "invalid timestamp format")
		}
		startTime = &t
	}
	if req.EndTime != "" {
		t, err := time.Parse(time.RFC3339, req.EndTime)
		if err != nil {
			return nil, twirp.InvalidArgumentError("end_time", "invalid timestamp format")
		}
		endTime = &t
	}

	// Get logs from database
	filter := database.LogsFilter{
		ApplicationID: appID,
		PageSize:      int(req.PageSize),
		Cursor:        cursor,
		LogLevel:      req.LogLevel,
		StartTime:     startTime,
		EndTime:       endTime,
	}

	logs, err := s.db.GetRecentLogs(filter)
	if err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	// Convert to response format
	pbLogs := make([]*pb.LogEntry, 0, len(logs))
	var lastTimestamp time.Time
	for _, log := range logs {
		// Convert string log level to pb.LogLevel enum
		var level pb.LogLevel
		switch log.Level {
		case "DEBUG":
			level = pb.LogLevel_DEBUG
		case "INFO":
			level = pb.LogLevel_INFO
		case "WARN":
			level = pb.LogLevel_WARN
		case "ERROR":
			level = pb.LogLevel_ERROR
		case "FATAL":
			level = pb.LogLevel_FATAL
		default:
			level = pb.LogLevel_UNKNOWN
		}

		pbLogs = append(pbLogs, &pb.LogEntry{
			LogId:     log.LogID.String(),
			Timestamp: log.Timestamp.Format(time.RFC3339),
			Level:     level,
			Message:   log.Message,
		})
		lastTimestamp = log.Timestamp
	}

	return &pb.GetLogsResponse{
		Logs:            pbLogs,
		HasMore:         len(logs) >= int(req.PageSize),
		NextCursor:      lastTimestamp.Format(time.RFC3339),
		TotalCount:      int32(len(logs)),
		ApplicationName: app.Name,
	}, nil
}

func (s *TwirpServer) GenerateDummyLogs(ctx context.Context, req *pb.GenerateDummyLogsRequest) (*pb.GenerateDummyLogsResponse, error) {
	// Validate token
	user, err := s.authService.ValidateToken(req.Token)
	if err != nil {
		return nil, twirp.NewError(twirp.Unauthenticated, "invalid token")
	}

	// Parse application ID
	appID, err := gocql.ParseUUID(req.ApplicationId)
	if err != nil {
		return nil, twirp.InvalidArgumentError("application_id", "invalid UUID format")
	}

	// Verify application ownership
	app, err := s.db.GetApplication(appID)
	if err != nil {
		return nil, twirp.NotFoundError("application not found")
	}
	if app.UserID != user.ID {
		return nil, twirp.NewError(twirp.PermissionDenied, "not authorized to access this application")
	}

	// Generate dummy logs
	count, err := s.db.GenerateDummyLogs(appID)
	if err != nil {
		return nil, twirp.InternalErrorWith(err)
	}

	return &pb.GenerateDummyLogsResponse{
		GeneratedCount: int32(count),
	}, nil
}
