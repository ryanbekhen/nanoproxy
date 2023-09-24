package basicauth

import (
	"crypto/subtle"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
)

type Config struct {
	Users        map[string]string
	Authorized   func(user string, pass string) bool
	Unauthorized func(*fiber.Ctx) error
}

var ConfigDefault = Config{
	Users:        map[string]string{},
	Authorized:   nil,
	Unauthorized: nil,
}

func configDefault(config ...Config) Config {
	if len(config) < 1 {
		return ConfigDefault
	}

	cfg := config[0]

	if cfg.Users == nil {
		cfg.Users = ConfigDefault.Users
	}

	if cfg.Authorized == nil {
		cfg.Authorized = func(user string, pass string) bool {
			userPass, exist := cfg.Users[user]
			return exist && subtle.ConstantTimeCompare(utils.UnsafeBytes(userPass), utils.UnsafeBytes(pass)) == 1
		}
	}

	if cfg.Unauthorized == nil {
		cfg.Unauthorized = func(c *fiber.Ctx) error {
			c.Set(fiber.HeaderProxyAuthenticate, "Basic realm=Restricted")
			return c.SendStatus(fiber.StatusProxyAuthRequired)
		}
	}

	return cfg
}
