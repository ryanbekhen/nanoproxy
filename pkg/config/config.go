package config

import "time"

type Config struct {
	Timezone      string        `env:"TZ" envDefault:"Local"`
	Network       string        `env:"NETWORK" envDefault:"tcp"`
	ADDR          string        `env:"ADDR" envDefault:":1080"`
	Credentials   []string      `env:"CREDENTIALS" envSeparator:","`
	ClientTimeout time.Duration `env:"CLIENT_TIMEOUT" envDefault:"15s"`
	DestTimeout   time.Duration `env:"DEST_TIMEOUT" envDefault:"15s"`
}
