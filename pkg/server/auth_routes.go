package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	aspb "github.com/hyperxpizza/auth-service/pkg/grpc"
	uspb "github.com/hyperxpizza/users-service/pkg/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	AuthServiceIDContext   = "authServiceID"
	UsersServiceIDContext  = "usersSerivceID"
	UsernameContext        = "username"
	NotFoundInContextError = "%s not found in the context"
	NotAuthorized          = "not authorized"
)

type loginRequest struct {
	username string `json:"username"`
	password string `json:"password"`
}

var bgContext = context.Background()

func (s *Server) Login(c *gin.Context) {

	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	loginData, err := s.usersServiceClient.GetLoginData(bgContext, &uspb.LoginRequest{Username: req.username, Password: req.password})
	if err != nil {
		st, ok := status.FromError(err)
		if !ok {
			c.Status(http.StatusInternalServerError)
			return
		}

		s := st.Proto()
		if s.Code == int32(codes.NotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"msg": "username not found in the users-service database",
			})
			return
		}

		c.Status(http.StatusInternalServerError)
		return
	}

	tokens, err := s.authServiceClient.GenerateToken(bgContext, &aspb.TokenRequest{Username: req.username, UsersServiceID: loginData.UserID})
	if err != nil {
		st, ok := status.FromError(err)
		if !ok {
			c.Status(http.StatusInternalServerError)
			return
		}

		s := st.Proto()
		if s.Code == int32(codes.NotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"msg": "username not found in the auth-service database",
			})
			return
		}

		c.Status(http.StatusInternalServerError)
		return

	}

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  tokens.AccessToken,
		"refreshToken": tokens.RefreshToken,
	})

}

type registerRequest struct {
	username  string `json:"username"`
	password1 string `json:"password1"`
	password2 string `json:"password2"`
	email     string `json:"email"`
}

func (s *Server) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	c.Status(http.StatusCreated)
}

func (s *Server) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := getTokenFromHeader(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": NotAuthorized,
			})
			c.Abort()
			return
		}

		token := aspb.AccessTokenData{AccessToken: tokenString}
		data, err := s.authServiceClient.ValidateToken(c, &token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": NotAuthorized,
			})
			c.Abort()
			return
		}

		c.Set(AuthServiceIDContext, data.AuthServiceID)
		c.Set(UsersServiceIDContext, data.UsersServiceID)
		c.Set(UsernameContext, data.Username)
		c.Next()
	}
}

func (s *Server) RefreshToken(c *gin.Context) {

}

func (s *Server) Logout(c *gin.Context) {

}

func getTokenFromHeader(r *http.Request) (string, error) {
	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer")
	if len(splitToken) != 2 {
		return "", errors.New("token not valid")
	}
	tokenString := strings.TrimSpace(splitToken[1])
	return tokenString, nil
}

func getContextData(c *gin.Context) (int64, int64, string, error) {

	asid, exists := c.Get(AuthServiceIDContext)
	if !exists {
		return 0, 0, "", fmt.Errorf(NotFoundInContextError, AuthServiceIDContext)
	}

	usid, exists := c.Get(UsersServiceIDContext)
	if !exists {
		return 0, 0, "", fmt.Errorf(NotFoundInContextError, UsersServiceIDContext)
	}

	username, exists := c.Get(UsernameContext)
	if !exists {
		return 0, 0, "", fmt.Errorf(NotFoundInContextError, UsernameContext)
	}

	return asid.(int64), usid.(int64), username.(string), nil
}
