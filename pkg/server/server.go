package server

import "github.com/sirupsen/logrus"

type Server struct {
	logger logrus.FieldLogger
}

func NewServer(configPath string, logger logrus.FieldLogger) (*Server, error) {}
