package logs

import "errors"

var (
	ErrInvalidAPIKey   = errors.New("invalid API key")
	ErrInvalidInput    = errors.New("invalid input")
	ErrUnauthorized    = errors.New("unauthorized")
	ErrTooManyLogs     = errors.New("too many logs in batch")
	ErrInvalidLogLevel = errors.New("invalid log level")
)
