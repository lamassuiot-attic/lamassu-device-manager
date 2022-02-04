package configs

import "github.com/kelseyhightower/envconfig"

type Config struct {
	Port             string `required:"true" split_words:"true"`
	Protocol         string `required:"true" split_words:"true"`
	PostgresUser     string `required:"true" split_words:"true"`
	PostgresDB       string `required:"true" split_words:"true"`
	PostgresPassword string `required:"true" split_words:"true"`
	PostgresHostname string `required:"true" split_words:"true"`
	PostgresPort     string `required:"true" split_words:"true"`

	CACertFile   string `required:"true" split_words:"true"`
	CAServerAddr string `required:"true" split_words:"true"`

	LamassuCACertFile string `split_words:"true"`
	LamassuCAAddress  string `split_words:"true"`

	MutualTLSEnabled  bool   `split_words:"true"`
	MutualTLSClientCA string `split_words:"true"`

	CertFile            string `required:"true" split_words:"true"`
	KeyFile             string `required:"true" split_words:"true"`
	MinimumReenrollDays string `required:"true" split_words:"true"`
}

func NewConfig(prefix string) (error, Config) {
	var cfg Config
	err := envconfig.Process(prefix, &cfg)
	if err != nil {
		return err, Config{}
	}
	return nil, cfg
}
