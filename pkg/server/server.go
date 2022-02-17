package server

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/hyperxpizza/api-gateway/pkg/config"
	grpcconnection "github.com/hyperxpizza/api-gateway/pkg/grpc-connection"
	aspb "github.com/hyperxpizza/auth-service/pkg/grpc"
	uspb "github.com/hyperxpizza/users-service/pkg/grpc"
	"github.com/sirupsen/logrus"
)

type Server struct {
	router             *gin.Engine
	logger             logrus.FieldLogger
	cfg                *config.Config
	authServiceClient  aspb.AuthServiceClient
	usersServiceClient uspb.UsersServiceClient
}

func NewServer(configPath string, logger logrus.FieldLogger) (*Server, error) {

	cfg, err := config.NewConfig(configPath)
	if err != nil {
		return nil, err
	}

	authServiceClient, err := grpcconnection.AuthServiceConnection(cfg.AuthService.Host, cfg.AuthService.CertPath, cfg.AuthService.Port)
	if err != nil {
		return nil, err
	}

	usersServiceClient, err := grpcconnection.UsersServiceConnection(cfg.UsersService.Host, cfg.UsersService.CertPath, cfg.UsersService.Port)
	if err != nil {
		return nil, err
	}

	gin.SetMode(cfg.Router.Mode)
	router := gin.Default()

	return &Server{
		logger:             logger,
		cfg:                cfg,
		router:             router,
		authServiceClient:  *authServiceClient,
		usersServiceClient: *usersServiceClient,
	}, nil

}

func (s *Server) Run() {
	s.setupRoutes()
	addr := fmt.Sprintf("%s:%d", s.cfg.Router.Host, s.cfg.Router.Port)
	s.router.Run(addr)
}

func (s *Server) setupRoutes() {
	api := s.router.Group("api")
	{
		auth := api.Group("auth")
		{
			auth.POST("/login", s.Login)
			auth.POST("/register", s.Register)
		}
	}
}
