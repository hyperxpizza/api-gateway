package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type Config struct {
	Router struct {
		Host string `json:"host"`
		Port int    `json:"port"`
		Mode string `json:"mode"`
	} `json:"router"`
	AuthService struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		CertPath string `json:"certPath"`
	} `json:"authService"`
}

func NewConfig(pathToFile string) (*Config, error) {
	file, err := os.Open(pathToFile)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var c Config

	err = json.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

func (c *Config) PrettyPrint() {
	data, _ := json.MarshalIndent(c, "", " ")
	fmt.Println(string(data))
}
