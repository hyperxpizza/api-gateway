package utils

import (
	"fmt"

	"google.golang.org/grpc/status"
)

func GetHTTPCodeFromStatus(err error) (int, error) {
	var code int

	st, ok := status.FromError(err)
	if !ok {
		return 0, err
	}

	fmt.Println(st.Code())
	fmt.Println(st.Message())

	return code, nil
}
