package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/hyperxpizza/api-gateway/pkg/utils"
	aspb "github.com/hyperxpizza/auth-service/pkg/grpc"
	uspb "github.com/hyperxpizza/users-service/pkg/grpc"
)

const (
	AuthServiceIDContext   = "authServiceID"
	UsersServiceIDContext  = "usersSerivceID"
	UsernameContext        = "username"
	NotFoundInContextError = "%s not found in the context"
	NotAuthorized          = "not authorized"
	UserNotFoundError      = "user: %s was not found"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var bgContext = context.Background()

func (s *Server) Login(c *gin.Context) {

	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	loginData, err := s.usersServiceClient.GetLoginData(bgContext, &uspb.LoginRequest{Username: req.Username, Password: req.Password})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{
				"msg": UserNotFoundError,
			})
			return
		}

		code := utils.GetHTTPCodeFromStatus(err)
		c.Status(code)
		return
	}

	tokens, err := s.authServiceClient.GenerateToken(bgContext, &aspb.TokenRequest{Username: req.Username, UsersServiceID: loginData.UserID})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{
				"msg": UserNotFoundError,
			})
			return
		}

		code := utils.GetHTTPCodeFromStatus(err)
		c.Status(code)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  tokens.AccessToken,
		"refreshToken": tokens.RefreshToken,
	})

}

type registerRequest struct {
	Username  string `json:"username"`
	Password1 string `json:"password1"`
	Password2 string `json:"password2"`
	Email     string `json:"email"`
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

type refreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func (s *Server) RefreshToken(c *gin.Context) {
	var req refreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	data := aspb.RefreshTokenData{RefreshToken: req.RefreshToken}
	tokens, err := s.authServiceClient.RefreshToken(bgContext, &data)
	if err != nil {
		code := utils.GetHTTPCodeFromStatus(err)
		c.Status(code)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  tokens.AccessToken,
		"refreshToken": tokens.RefreshToken,
	})

}

func (s *Server) Logout(c *gin.Context) {
	asid, usid, username, err := getContextData(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"err": err.Error(),
		})
	}

	data := aspb.TokenData{
		Username:       username,
		AuthServiceID:  asid,
		UsersServiceID: usid,
	}
	_, err = s.authServiceClient.DeleteTokens(bgContext, &data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"err": err.Error(),
		})
	}

	c.Status(http.StatusNoContent)
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
