package errors

import "net/http"

type RestErr struct {
	Error   string `json:"error"`
	Status  int    `json:"status"`
	Message string `json:"message"`
}

func NewBadRequestError(message string) *RestErr {
	return &RestErr{
		Error:   "err_bad_request",
		Status:  http.StatusBadRequest,
		Message: message,
	}
}

func NewInternalServerError(message string) *RestErr {
	return &RestErr{
		Error:   "internal_server_error",
		Status:  http.StatusInternalServerError,
		Message: message,
	}
}

func NewNotFoundError(message string) *RestErr {
	return &RestErr{
		Error:   "not_found_error",
		Status:  http.StatusNotFound,
		Message: message,
	}
}
