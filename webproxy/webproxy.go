package webproxy

import (
	"encoding/base64"
	"github.com/rs/zerolog"
	"github.com/valyala/fasthttp"
	"io"
	"net"
	"strings"
	"time"
)

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

type WebProxy struct {
	TunnelTimeout time.Duration // tunnel timeout in seconds (default 15s)
	Logger        zerolog.Logger
	BasicAuth     string
}

func New(basic string, tunnelTimeout time.Duration, logger zerolog.Logger) *WebProxy {
	return &WebProxy{
		BasicAuth:     basic,
		TunnelTimeout: tunnelTimeout,
		Logger:        logger,
	}
}

// Handler handles incoming HTTP requests and proxies them to the destination server
func (s *WebProxy) Handler(ctx *fasthttp.RequestCtx) {
	// check for basic auth
	if s.BasicAuth != "" {
		proxyAuth := string(ctx.Request.Header.Peek("Proxy-Authorization"))
		if proxyAuth == "" {
			ctx.Logger().Printf("Requires authentication")
			ctx.Error("Requires authentication", fasthttp.StatusProxyAuthRequired)
			return
		}

		proxyAuth = strings.TrimPrefix(proxyAuth, "Basic ")
		base64Io := base64.NewDecoder(base64.StdEncoding, strings.NewReader(proxyAuth))

		// read the decoded username:password
		decoded, err := io.ReadAll(base64Io)
		if err != nil {
			ctx.Logger().Printf("Decoding error: %s", err.Error())
			ctx.Error(err.Error(), fasthttp.StatusBadRequest)
			return
		}

		if string(decoded) != s.BasicAuth {
			ctx.Logger().Printf("Unauthorized")
			ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
			return
		}
	}

	// remove hop-by-hop headers
	removeHopHeaders(&ctx.Request.Header)

	if string(ctx.Method()) == fasthttp.MethodConnect {
		s.handleTunneling(ctx)
	} else {
		s.handleHTTP(ctx)
	}
}

// handleTunneling handles CONNECT requests by establishing two-way connections to both the client and server
func (s *WebProxy) handleTunneling(ctx *fasthttp.RequestCtx) {
	defer s.loggerDetails("TUNNEL", ctx)

	destConn, err := fasthttp.DialTimeout(string(ctx.Host()), s.TunnelTimeout)
	if err != nil {
		ctx.Error(err.Error(), fasthttp.StatusServiceUnavailable)
		return
	}

	// send a 200 OK response to client to establish a tunnel connection with the destination server
	ctx.SetStatusCode(fasthttp.StatusOK)

	// hijack the client connection from the HTTP server
	ctx.Hijack(func(clientConn net.Conn) {
		defer func() {
			_ = clientConn.Close()
			_ = destConn.Close()
		}()
		go transfer(destConn, clientConn)
		transfer(clientConn, destConn)
	})
}

// handleHTTP handles standard HTTP proxy requests
func (s *WebProxy) handleHTTP(ctx *fasthttp.RequestCtx) {
	defer s.loggerDetails("HTTP", ctx)

	// create a new HTTP request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	// create a new HTTP response
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// copy the original request to the new request
	req.SetRequestURIBytes(ctx.RequestURI())
	req.Header.SetMethodBytes(ctx.Method())
	req.Header.SetHostBytes(ctx.Host())
	copyHeaderRequest(&req.Header, &ctx.Request.Header)

	if err := fasthttp.DoTimeout(req, resp, s.TunnelTimeout); err != nil {
		ctx.Error(err.Error(), fasthttp.StatusServiceUnavailable)
		return
	}

	copyHeaderResponse(&ctx.Response.Header, &resp.Header)
	ctx.SetStatusCode(resp.StatusCode())
	ctx.SetBody(resp.Body())
}

// removeHopHeaders removes hop-by-hop headers to the backend.
func removeHopHeaders(header *fasthttp.RequestHeader) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func (s *WebProxy) loggerDetails(message string, ctx *fasthttp.RequestCtx) {
	latency := time.Since(ctx.Time())
	s.Logger.Info().
		Str("ip", extractClientAddressFromRequest(ctx)).
		Str("url", string(ctx.RequestURI())).
		Str("latency", latency.String()).
		Msg(message)
}

// copyHeader copies header from src to dst.
func copyHeaderRequest(dst *fasthttp.RequestHeader, src *fasthttp.RequestHeader) {
	src.VisitAll(func(key, value []byte) {
		dst.AddBytesKV(key, value)
	})
}

// copyHeader copies header from src to dst.
func copyHeaderResponse(dst *fasthttp.ResponseHeader, src *fasthttp.ResponseHeader) {
	src.VisitAll(func(key, value []byte) {
		dst.AddBytesKV(key, value)
	})
}

// transfer bytes from src to dst until either EOF is reached on src or an error occurs
func transfer(destination io.Writer, source io.Reader) {
	_, _ = io.Copy(destination, source)
}

// extractClientAddressFromRequest extracts the client address from the request headers
func extractClientAddressFromRequest(ctx *fasthttp.RequestCtx) string {
	clientAddr := string(ctx.Request.Header.Peek("X-Forwarded-For"))
	if len(clientAddr) > 0 {
		clientAddr = strings.Split(clientAddr, ",")[0]
	} else {
		clientAddr = string(ctx.Request.Header.Peek("CF-Connecting-IP"))
		if len(clientAddr) > 0 {
			clientAddr = strings.Split(clientAddr, ",")[0]
		} else {
			clientAddr = string(ctx.Request.Header.Peek("X-Real-IP"))
			if len(clientAddr) > 0 {
				clientAddr = strings.Split(clientAddr, ",")[0]
			} else {
				clientAddr = ctx.RemoteIP().String()
			}
		}
	}

	return clientAddr
}
