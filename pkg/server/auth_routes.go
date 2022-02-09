package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	aspb "github.com/hyperxpizza/auth-service/pkg/grpc"
)

func (s *Server) Login(c *gin.Context) {}

func (s *Server) Register(c *gin.Context) {}

func (s *Server) SignOut(c *gin.Context) {}

func (s *Server) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := getTokenFromHeader(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Not Authorized",
			})
			c.Abort()
			return
		}

		token := aspb.Token{Token: tokenString}
		data, err := s.authServiceClient.ValidateToken(c, &token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Not Authorized",
			})
			c.Abort()
			return
		}

		c.Set("id", data.Id)
		c.Set("username", data.Username)
		c.Next()
	}
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
