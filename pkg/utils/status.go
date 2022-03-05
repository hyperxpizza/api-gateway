package utils

import (
	"fmt"
	"net/http"

	"google.golang.org/grpc/status"
)

func GetHTTPCodeFromStatus(err error) int {
	var code int

	st, ok := status.FromError(err)
	if !ok {
		return http.StatusInternalServerError
	}

	fmt.Println(st.Proto().Code)

	switch st.Proto().Code {
	case 3:
		return http.StatusBadRequest
	case 7:
		return http.StatusUnauthorized
	case 5:
		return http.StatusNotFound
	case 13:
		return http.StatusInternalServerError
	case 16:
		return http.StatusUnauthorized
	}

	return code
}
