package webproxy

import (
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
	"io"
	"net"
	"time"
)

type WebProxy struct {
	TunnelTimeout time.Duration // tunnel timeout in seconds (default 15s)
}

func New(tunnelTimeout time.Duration) *WebProxy {
	return &WebProxy{
		TunnelTimeout: tunnelTimeout,
	}
}

// Handler handles incoming HTTP requests and proxies them to the destination server
func (s *WebProxy) Handler(c *fiber.Ctx) error {
	if c.Method() == fiber.MethodConnect {
		return s.handleTunneling(c)
	} else {
		return s.handleHTTP(c)
	}
}

// handleHTTP handles normal HTTP proxy requests
func (s *WebProxy) handleHTTP(c *fiber.Ctx) error {
	agent := fiber.AcquireAgent()

	// set request URI and Host header
	req := agent.Request()
	req.SetRequestURI(c.OriginalURL())
	req.Header.SetMethod(c.Method())
	req.Header.SetHost(c.Hostname())

	// copy headers
	c.Request().Header.CopyTo(&req.Header)

	// parse request
	if err := agent.Parse(); err != nil {
		return err
	}

	// send request and receive response
	var resp fiber.Response
	if err := agent.DoTimeout(req, &resp, s.TunnelTimeout); err != nil {
		return c.SendStatus(fiber.StatusBadGateway)
	}

	// copy response headers
	resp.Header.CopyTo(&c.Response().Header)

	// set status code
	return c.Status(resp.StatusCode()).Send(resp.Body())
}

// handleTunneling handles CONNECT requests
func (s *WebProxy) handleTunneling(c *fiber.Ctx) error {
	destConn, err := fasthttp.DialTimeout(c.OriginalURL(), s.TunnelTimeout)
	if err != nil {
		return c.SendStatus(fiber.StatusBadGateway)
	}

	// hijack the client connection from the HTTP server
	c.Context().Hijack(func(clientConn net.Conn) {
		go transfer(destConn, clientConn)
		transfer(clientConn, destConn)
	})

	return nil
}

// transfer bytes from src to dst until either EOF is reached on src or an error occurs
func transfer(destination net.Conn, source net.Conn) {
	defer func() {
		_ = destination.Close()
		_ = source.Close()
	}()
	_, _ = io.Copy(destination, source)
}
