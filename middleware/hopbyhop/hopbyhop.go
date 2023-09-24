package hopbyhop

import "github.com/gofiber/fiber/v2"

// Hop-by-hop headers. These are removed when sent to the backend.
// (https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func New() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// remove hop-by-hop headers
		for _, h := range hopHeaders {
			c.Request().Header.Del(h)
		}
		return c.Next()
	}
}
