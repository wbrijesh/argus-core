package applications

import "errors"

var (
	ErrApplicationNotFound = errors.New("application not found")
	ErrUnauthorized        = errors.New("unauthorized")
	ErrInvalidInput        = errors.New("invalid input")
)
