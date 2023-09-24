package basicauth

import (
	"encoding/base64"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	"io"
	"net/http/httptest"
	"testing"
)

func Test_Middleware_BasicAuth(t *testing.T) {
	t.Parallel()

	app := fiber.New()

	app.Use(New(Config{
		Users: map[string]string{
			"john": "doe",
			"jane": "doe",
		},
	}))

	app.Get("/testauth", func(c *fiber.Ctx) error {
		username := c.Locals("username").(string)
		password := c.Locals("password").(string)

		return c.SendString(username + password)
	})

	tests := []struct {
		url        string
		statusCode int
		username   string
		password   string
	}{
		{
			url:        "/testauth",
			statusCode: fiber.StatusOK,
			username:   "john",
			password:   "doe",
		},
		{
			url:        "/testauth",
			statusCode: fiber.StatusOK,
			username:   "jane",
			password:   "doe",
		},
		{
			url:        "/testauth",
			statusCode: fiber.StatusProxyAuthRequired,
			username:   "john",
			password:   "wrong",
		},
	}

	for _, tt := range tests {
		// Encode credentials to base64
		cred := base64.StdEncoding.EncodeToString([]byte(tt.username + ":" + tt.password))

		req := httptest.NewRequest(fiber.MethodGet, "/testauth", nil)
		req.Header.Set(fiber.HeaderProxyAuthorization, "Basic "+cred)
		resp, err := app.Test(req)
		utils.AssertEqual(t, nil, err)

		body, err := io.ReadAll(resp.Body)
		utils.AssertEqual(t, nil, err)

		utils.AssertEqual(t, tt.statusCode, resp.StatusCode)
		if tt.statusCode == fiber.StatusOK {
			utils.AssertEqual(t, tt.username+tt.password, string(body))
		}
	}
}

func Test_Middleware_BasicAuth_No_Users(t *testing.T) {
	t.Parallel()

	app := fiber.New()

	app.Use(New(Config{
		Users: map[string]string{},
	}))

	app.Get("/testauth", func(c *fiber.Ctx) error {
		return c.SendString("testauth")
	})

	req := httptest.NewRequest(fiber.MethodGet, "/testauth", nil)
	resp, err := app.Test(req)
	utils.AssertEqual(t, nil, err)

	body, err := io.ReadAll(resp.Body)
	utils.AssertEqual(t, nil, err)

	utils.AssertEqual(t, fiber.StatusOK, resp.StatusCode)
	utils.AssertEqual(t, "testauth", string(body))
}
