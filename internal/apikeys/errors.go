package apikeys

import "errors"

var (
	ErrAPIKeyInvalid = errors.New("invalid API key")
	ErrAPIKeyExpired = errors.New("API key expired")
	ErrAPIKeyRevoked = errors.New("API key revoked")
	ErrUnauthorized  = errors.New("unauthorized")
)
