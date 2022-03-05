package main

import (
	"testing"

	"github.com/hyperxpizza/api-gateway/pkg/utils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestStatusFromErr(t *testing.T) {
	err := status.Error(codes.Unauthenticated, "not found")
	utils.GetHTTPCodeFromStatus(err)
}
