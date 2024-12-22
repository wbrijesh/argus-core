package logs

import (
	pb "argus-core/rpc/logs"
	"fmt"
	"time"
)

const (
    MaxBatchSize = 1000
    MaxMessageLength = 10000
)

func validateSendLogsRequest(req *pb.SendLogsRequest) error {
    if req.ApiKey == "" {
        return fmt.Errorf("%w: API key is required", ErrInvalidInput)
    }

    if len(req.Logs) == 0 {
        return fmt.Errorf("%w: no logs provided", ErrInvalidInput)
    }

    if len(req.Logs) > MaxBatchSize {
        return fmt.Errorf("%w: maximum batch size is %d", ErrTooManyLogs, MaxBatchSize)
    }

    for i, log := range req.Logs {
        if log.Message == "" {
            return fmt.Errorf("%w: empty message in log entry %d", ErrInvalidInput, i)
        }
        if len(log.Message) > MaxMessageLength {
            return fmt.Errorf("%w: message too long in log entry %d", ErrInvalidInput, i)
        }
        if log.Level == pb.LogLevel_UNKNOWN {
            return fmt.Errorf("%w: invalid log level in entry %d", ErrInvalidLogLevel, i)
        }
    }

    return nil
}

func validateGetLogsRequest(req *pb.GetLogsRequest) error {
    if req.Token == "" {
        return fmt.Errorf("%w: token is required", ErrInvalidInput)
    }

    if req.ApplicationId == "" {
        return fmt.Errorf("%w: application ID is required", ErrInvalidInput)
    }

    if req.StartTime != "" {
        if _, err := time.Parse(time.RFC3339, req.StartTime); err != nil {
            return fmt.Errorf("%w: invalid start time format, use RFC3339", ErrInvalidInput)
        }
    }

    return nil
}
