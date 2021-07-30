package configs

import "github.com/kelseyhightower/envconfig"

type Config struct {
	Port string

	PostgresUser     string
	PostgresDB       string
	PostgresPassword string
	PostgresHostname string
	PostgresPort     string

	ConsulProtocol string
	ConsulHost     string
	ConsulPort     string
	ConsulCA       string

	KeycloakHostname     string
	KeycloakPort         string
	KeycloakProtocol     string
	KeycloakRealm        string
	KeycloakCA           string
	KeycloakClientId     string
	KeycloakClientSecret string

	CACertfile   string
	CAServerAddr string

	CertFile            string
	KeyFile             string
	MinimumReenrollDays string
}

func NewConfig(prefix string) (error, Config) {
	var cfg Config
	err := envconfig.Process(prefix, &cfg)
	if err != nil {
		return err, Config{}
	}
	return nil, cfg
}
