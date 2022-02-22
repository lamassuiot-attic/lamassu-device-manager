package errors

import (
	"fmt"
)

type ValidationError struct {
	Msg string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s", e.Msg)
}

type GenericError struct {
	Message    string
	StatusCode int
}

func (e *GenericError) Error() string {
	return fmt.Sprintf("%s", e.Message)
}
