package basicauth

import (
	"encoding/base64"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	"strings"
)

func New(config Config) fiber.Handler {
	cfg := configDefault(config)
	return func(c *fiber.Ctx) error {
		// Skip if basic auth is empty
		if len(cfg.Users) == 0 {
			return c.Next()
		}

		// Get authorization header
		auth := c.Get(fiber.HeaderProxyAuthorization)

		// Check if header is valid
		if len(auth) < 6 || !utils.EqualFold(auth[:6], "basic ") {
			return cfg.Unauthorized(c)
		}

		// Decode header
		raw, err := base64.StdEncoding.DecodeString(auth[6:])
		if err != nil {
			return cfg.Unauthorized(c)
		}

		// Get credentials
		creds := utils.UnsafeString(raw)

		// Split username and password
		index := strings.Index(creds, ":")
		if index == -1 {
			return cfg.Unauthorized(c)
		}

		// Get username and password
		user := creds[:index]
		pass := creds[index+1:]

		// Check credentials
		if cfg.Authorized(user, pass) {
			c.Locals("username", user)
			c.Locals("password", pass)
			return c.Next()
		}

		// Credentials doesn't match
		return cfg.Unauthorized(c)
	}
}
