package config

import "time"

type Config struct {
	Timezone            string        `env:"TZ" envDefault:"Local"`
	Network             string        `env:"NETWORK" envDefault:"tcp"`
	ADDR                string        `env:"ADDR" envDefault:":1080"`
	ADDRHttp            string        `env:"ADDR_HTTP" envDefault:":8080"`
	ADDRAdmin           string        `env:"ADDR_ADMIN" envDefault:":9090"`
	Credentials         []string      `env:"CREDENTIALS" envSeparator:","`
	ClientTimeout       time.Duration `env:"CLIENT_TIMEOUT" envDefault:"15s"`
	DestTimeout         time.Duration `env:"DEST_TIMEOUT" envDefault:"15s"`
	TorEnabled          bool          `env:"TOR_ENABLED" envDefault:"false"`
	TorIdentityInterval time.Duration `env:"TOR_IDENTITY_INTERVAL" envDefault:"10m"`
	UsersFile           string        `env:"USERS_FILE" envDefault:"/etc/nanoproxy/users.json"`
	AdminEnabled        bool          `env:"ADMIN_ENABLED" envDefault:"true"`
}
