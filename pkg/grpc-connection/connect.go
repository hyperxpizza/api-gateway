package grpcconn

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	aspb "github.com/hyperxpizza/auth-service/pkg/grpc"
	uspb "github.com/hyperxpizza/users-service/pkg/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func loadTLSCredentials(certPath string) (credentials.TransportCredentials, error) {
	path := fmt.Sprintf("%s/ca-cert.pem", certPath)
	pemServerCert, err := ioutil.ReadFile(path)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCert) {
		return nil, errors.New("failed to add server CA's certificate")
	}

	conf := &tls.Config{
		RootCAs: certPool,
	}

	return credentials.NewTLS(conf), nil
}

func grpcConnection(host string, port int) (*grpc.ClientConn, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	connection, err := grpc.Dial(addr)
	if err != nil {
		return nil, err
	}

	return connection, nil
}

func AuthServiceConnection(host, certPath string, port int) (*aspb.AuthServiceClient, error) {
	conn, err := grpcConnection(host, port)
	if err != nil {
		return nil, err
	}

	client := aspb.NewAuthServiceClient(conn)
	return &client, nil
}

func UsersServiceConnection(host, certPath string, port int) (*uspb.UsersServiceClient, error) {
	conn, err := grpcConnection(host, port)
	if err != nil {
		return nil, err
	}

	client := uspb.NewUsersServiceClient(conn)
	return &client, nil
}
