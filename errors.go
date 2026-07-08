package hax

import "fmt"

// HaxError is the base error for all HAX SDK errors.
type HaxError struct {
	Message    string
	Details    map[string]any
	StatusCode int
}

func (e *HaxError) Error() string {
	if len(e.Details) > 0 {
		return fmt.Sprintf("%s: %v", e.Message, e.Details)
	}
	return e.Message
}

// AuthenticationError is raised when API authentication fails (401).
type AuthenticationError struct {
	HaxError
}

// ForbiddenError is raised when access is forbidden (403).
type ForbiddenError struct {
	HaxError
	Code string
}

// NotFoundError is raised when a resource is not found (404).
type NotFoundError struct {
	HaxError
}

// ValidationError is raised when request validation fails (422).
type ValidationError struct {
	HaxError
}

// RateLimitError is raised when rate limited (429).
type RateLimitError struct {
	HaxError
	RetryAfter int
	Limit      int
	Used       int
	Remaining  int
	ResetsAt   string
}

// ServerError is raised for server errors (5xx).
type ServerError struct {
	HaxError
}

// DecryptionError is raised when decryption fails.
type DecryptionError struct {
	HaxError
}

func newHaxError(message string, details map[string]any, statusCode int) *HaxError {
	if details == nil {
		details = map[string]any{}
	}
	return &HaxError{
		Message:    message,
		Details:    details,
		StatusCode: statusCode,
	}
}

func authenticationError(message string, details map[string]any) *AuthenticationError {
	return &AuthenticationError{
		HaxError: *newHaxError(message, details, 401),
	}
}

func forbiddenError(message string, details map[string]any) *ForbiddenError {
	code := ""
	if details != nil {
		if c, ok := details["code"].(string); ok {
			code = c
		}
	}
	return &ForbiddenError{
		HaxError: *newHaxError(message, details, 403),
		Code:     code,
	}
}

func notFoundError(message string, details map[string]any) *NotFoundError {
	return &NotFoundError{
		HaxError: *newHaxError(message, details, 404),
	}
}

func validationError(message string, details map[string]any) *ValidationError {
	return &ValidationError{
		HaxError: *newHaxError(message, details, 422),
	}
}

func rateLimitError(message string, retryAfter int, details map[string]any) *RateLimitError {
	e := &RateLimitError{
		HaxError:   *newHaxError(message, details, 429),
		RetryAfter: retryAfter,
	}
	if details != nil {
		if v, ok := details["limit"]; ok {
			if n, ok := toInt(v); ok {
				e.Limit = n
			}
		}
		if v, ok := details["used"]; ok {
			if n, ok := toInt(v); ok {
				e.Used = n
			}
		}
		if v, ok := details["remaining"]; ok {
			if n, ok := toInt(v); ok {
				e.Remaining = n
			}
		}
		if v, ok := details["resetsAt"].(string); ok {
			e.ResetsAt = v
		}
	}
	return e
}

func serverError(message string, statusCode int, details map[string]any) *ServerError {
	return &ServerError{
		HaxError: *newHaxError(message, details, statusCode),
	}
}

func decryptionError(message string) *DecryptionError {
	return &DecryptionError{
		HaxError: *newHaxError(message, nil, 0),
	}
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case float32:
		return int(n), true
	}
	return 0, false
}
