package config

import "time"

type Config struct {
	Timezone              string        `env:"TZ" envDefault:"Local"`
	LogLevel              string        `env:"LOG_LEVEL" envDefault:"info"`
	Network               string        `env:"NETWORK" envDefault:"tcp"`
	ADDR                  string        `env:"ADDR" envDefault:":1080"`
	ADDRHttp              string        `env:"ADDR_HTTP" envDefault:":8080"`
	ADDRAdmin             string        `env:"ADDR_ADMIN" envDefault:":9090"`
	UserStorePath         string        `env:"USER_STORE_PATH" envDefault:"nanoproxy-data.db"`
	AdminCookieSecure     bool          `env:"ADMIN_COOKIE_SECURE" envDefault:"false"`
	AdminMaxLoginAttempts int           `env:"ADMIN_MAX_LOGIN_ATTEMPTS" envDefault:"5"`
	AdminLoginWindow      time.Duration `env:"ADMIN_LOGIN_WINDOW" envDefault:"5m"`
	AdminLockoutDuration  time.Duration `env:"ADMIN_LOCKOUT_DURATION" envDefault:"10m"`
	AdminAllowedOrigins   []string      `env:"ADMIN_ALLOWED_ORIGINS" envSeparator:","`
	ClientTimeout         time.Duration `env:"CLIENT_TIMEOUT" envDefault:"15s"`
	DestTimeout           time.Duration `env:"DEST_TIMEOUT" envDefault:"15s"`
	TorEnabled            bool          `env:"TOR_ENABLED" envDefault:"false"`
	TorIdentityInterval   time.Duration `env:"TOR_IDENTITY_INTERVAL" envDefault:"10m"`
}
