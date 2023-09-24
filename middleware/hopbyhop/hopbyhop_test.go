package hopbyhop

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	"io"
	"net/http/httptest"
	"testing"
)

// go test -run Test_Middleware_HopByHop
func Test_Middleware_HopByHop(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Use(New()).Get("/test", func(c *fiber.Ctx) error {
		return c.Send(c.Request().Header.Header())
	})

	// request with hop-by-hop headers
	req := httptest.NewRequest(fiber.MethodGet, "/test", nil)
	req.Header.Set("Proxy-Connection", "close")
	req.Header.Set("Test", "test")

	resp, err := app.Test(req)
	utils.AssertEqual(t, nil, err)

	body, err := io.ReadAll(resp.Body)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, "GET /test HTTP/1.1\r\nHost: example.com\r\nTest: test\r\n\r\n", string(body))
}
