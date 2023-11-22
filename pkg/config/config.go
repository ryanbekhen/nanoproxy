package config

type Config struct {
	Timezone string `env:"TZ" envDefault:"Local"`
	Network  string `env:"NETWORK" envDefault:"tcp"`
	ADDR     string `env:"ADDR" envDefault:":1080"`
}
