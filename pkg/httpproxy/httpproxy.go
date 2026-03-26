package httpproxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/ryanbekhen/nanoproxy/pkg/credential"
	"github.com/ryanbekhen/nanoproxy/pkg/resolver"
	"github.com/ryanbekhen/nanoproxy/pkg/traffic"
)

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

type Config struct {
	Credentials       credential.Store
	Logger            *zerolog.Logger
	DestConnTimeout   time.Duration
	ClientConnTimeout time.Duration
	Dial              func(network, addr string) (net.Conn, error)
	Resolver          resolver.Resolver
	Tracker           *traffic.Tracker
}

type Server struct {
	config *Config
}

var (
	ErrMissingProxyAuthorization = errors.New("missing proxy authorization header")
	ErrInvalidProxyAuthorization = errors.New("invalid proxy authorization header")
	ErrInvalidProxyCredentials   = errors.New("invalid credentials")
)

func New(conf *Config) *Server {
	if conf.Logger == nil {
		logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Timestamp().Logger()
		conf.Logger = &logger
	}

	if conf.Resolver == nil {
		conf.Resolver = &resolver.DNSResolver{}
	}

	if conf.DestConnTimeout == 0 {
		conf.DestConnTimeout = 5 * time.Second
	}

	if conf.ClientConnTimeout == 0 {
		conf.ClientConnTimeout = 5 * time.Second
	}

	server := &Server{
		config: conf,
	}

	return server
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
	} else {
		s.handleHTTP(w, r)
	}
}

func (s *Server) authenticateRequest(r *http.Request) (string, error) {
	if s.config.Credentials == nil {
		return "anonymous", nil
	}

	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		return "", ErrMissingProxyAuthorization
	}

	if strings.HasPrefix(authHeader, "Basic ") {
		encodedCreds := strings.TrimPrefix(authHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encodedCreds)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrInvalidProxyAuthorization, err)
		}

		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return "", ErrInvalidProxyAuthorization
		}

		username, password := parts[0], parts[1]
		if s.config.Credentials.Valid(username, password) {
			return username, nil
		}
		return "", ErrInvalidProxyCredentials
	}

	return "", ErrInvalidProxyAuthorization
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	requestLogger := s.requestLogger(r)
	username, err := s.authenticateRequest(r)
	if err != nil {
		requestLogger.Error().
			Err(err).
			Msg("proxy authentication failed")
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Restricted area\"")
		http.Error(w, "Proxy authentication required or unauthorized", http.StatusProxyAuthRequired)
		return
	}
	session := s.startSession(username, r.RemoteAddr)
	defer session.Close()

	startTime := time.Now()
	serverConn, err := s.config.Dial("tcp", r.Host)
	latency := time.Since(startTime).Milliseconds()
	if err != nil {
		requestLogger.Error().
			Str("dest_addr", r.Host).
			Str("latency", fmt.Sprintf("%dms", latency)).
			Err(err).
			Msg("connect failed")
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer serverConn.Close()

	clientConn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		requestLogger.Error().
			Err(err).
			Msg("failed to hijack client connection")
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	uploadCh := make(chan struct{}, 1)
	go func() {
		n, _ := io.Copy(serverConn, clientConn)
		session.AddUpload(n)
		uploadCh <- struct{}{}
	}()

	n, _ := io.Copy(clientConn, serverConn)
	session.AddDownload(n)
	<-uploadCh
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	requestLogger := s.requestLogger(r)
	username, err := s.authenticateRequest(r)
	if err != nil {
		requestLogger.Error().
			Err(err).
			Msg("proxy authentication failed")
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Restricted area\"")
		http.Error(w, "Proxy authentication required or unauthorized", http.StatusProxyAuthRequired)
		return
	}
	session := s.startSession(username, r.RemoteAddr)
	defer session.Close()

	startTime := time.Now()

	targetURL, err := normalizeProxyTargetURL(r)
	if err != nil {
		requestLogger.Error().
			Str("dest_addr", r.URL.String()).
			Err(err).
			Msg("invalid proxy target url")
		http.Error(w, "Invalid target URL", http.StatusBadRequest)
		return
	}

	proxyReqBody := &countingReadCloser{
		ReadCloser: r.Body,
		onRead: func(n int64) {
			session.AddUpload(n)
		},
	}

	resolvedAddr, err := resolveProxyTargetAddr(targetURL, s.config.Resolver)
	if err != nil {
		latency := time.Since(startTime).Milliseconds()
		requestLogger.Error().
			Str("dest_addr", targetURL.String()).
			Str("latency", fmt.Sprintf("%dms", latency)).
			Err(err).
			Msg("failed to resolve target host")
		http.Error(w, "Bad gateway: failed to resolve target host", http.StatusBadGateway)
		return
	}

	serverConn, err := dialProxyTarget(targetURL, resolvedAddr, s.config.Dial, s.config.ClientConnTimeout)
	if err != nil {
		latency := time.Since(startTime).Milliseconds()
		requestLogger.Error().
			Str("dest_addr", targetURL.String()).
			Str("latency", fmt.Sprintf("%dms", latency)).
			Err(err).
			Msg("failed to connect to target")
		http.Error(w, "Bad gateway: failed to send request", http.StatusBadGateway)
		return
	}
	defer serverConn.Close()

	proxyReq := buildOutboundProxyRequest(r, targetURL, proxyReqBody)
	if err := proxyReq.Write(serverConn); err != nil {
		latency := time.Since(startTime).Milliseconds()
		requestLogger.Error().
			Str("dest_addr", targetURL.String()).
			Str("latency", fmt.Sprintf("%dms", latency)).
			Err(err).
			Msg("failed to send request")
		http.Error(w, "Bad gateway: failed to send request", http.StatusBadGateway)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(serverConn), proxyReq)
	latency := time.Since(startTime).Milliseconds()
	if err != nil {
		requestLogger.Error().
			Str("dest_addr", targetURL.String()).
			Str("latency", fmt.Sprintf("%dms", latency)).
			Err(err).
			Msg("failed to read response")
		http.Error(w, "Bad gateway: failed to read response", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for _, key := range hopHeaders {
		resp.Header.Del(key)
	}

	for key, values := range resp.Header {
		if !isHopHeader(key) {
			w.Header()[key] = values
		}
	}

	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	session.AddDownload(n)
}

func (s *Server) startSession(username, remoteAddr string) *traffic.Session {
	if s.config.Tracker == nil {
		return nil
	}
	return s.config.Tracker.Start(username, extractClientIP(remoteAddr))
}

func extractClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func (s *Server) requestLogger(r *http.Request) zerolog.Logger {
	logger := s.config.Logger.With().Str("protocol", "http")
	if r != nil {
		logger = logger.Str("http_method", r.Method)
		if r.RemoteAddr != "" {
			logger = logger.Str("client_addr", r.RemoteAddr)
		}
	}
	return logger.Logger()
}

func resolveProxyTargetAddr(targetURL *url.URL, res resolver.Resolver) (string, error) {
	hostname := targetURL.Hostname()
	port := targetURL.Port()
	if port == "" {
		if targetURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	var ipStr string
	// If hostname is already a valid IP address, use it directly without DNS.
	if ip := net.ParseIP(hostname); ip != nil {
		ipStr = ip.String()
	} else {
		resolved, err := res.Resolve(hostname)
		if err != nil {
			return "", fmt.Errorf("resolve %q: %w", hostname, err)
		}
		ipStr = resolved.String()
	}

	return net.JoinHostPort(ipStr, port), nil
}

func normalizeProxyTargetURL(r *http.Request) (*url.URL, error) {
	if r == nil || r.URL == nil {
		return nil, fmt.Errorf("missing target url")
	}

	rawURL := r.URL
	scheme := strings.ToLower(strings.TrimSpace(rawURL.Scheme))
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported url scheme: %q", rawURL.Scheme)
	}

	if rawURL.User != nil {
		return nil, fmt.Errorf("userinfo is not allowed")
	}

	host := strings.TrimSpace(rawURL.Host)
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return nil, fmt.Errorf("missing url host")
	}

	hostname := host
	if strings.Contains(host, ":") {
		h, port, err := net.SplitHostPort(host)
		if err != nil {
			return nil, fmt.Errorf("invalid host:port")
		}
		if port != "" {
			p, err := strconv.Atoi(port)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port")
			}
		}
		hostname = h
	}

	if hostname == "" {
		return nil, fmt.Errorf("missing hostname")
	}

	normalized := &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     rawURL.EscapedPath(),
		RawPath:  rawURL.RawPath,
		RawQuery: rawURL.RawQuery,
	}

	if normalized.Path == "" {
		normalized.Path = "/"
	}

	return normalized, nil
}

func buildOutboundProxyRequest(r *http.Request, targetURL *url.URL, body io.ReadCloser) *http.Request {
	proxyReq := r.Clone(r.Context())
	proxyReq.URL = &url.URL{
		Path:     targetURL.Path,
		RawPath:  targetURL.RawPath,
		RawQuery: targetURL.RawQuery,
	}
	proxyReq.Host = targetURL.Host
	proxyReq.RequestURI = ""
	proxyReq.Body = body
	proxyReq.Close = true
	proxyReq.Header = make(http.Header, len(r.Header))

	for key, values := range r.Header {
		if isHopHeader(key) {
			continue
		}

		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	return proxyReq
}

func dialProxyTarget(targetURL *url.URL, resolvedAddr string, dial func(network, addr string) (net.Conn, error), timeout time.Duration) (net.Conn, error) {
	conn, err := dial("tcp", resolvedAddr)
	if err != nil {
		return nil, err
	}

	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	if targetURL.Scheme != "https" {
		return conn, nil
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: targetURL.Hostname(),
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	if timeout > 0 {
		_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	}

	return tlsConn, nil
}

type countingReadCloser struct {
	io.ReadCloser
	onRead func(n int64)
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if n > 0 && c.onRead != nil {
		c.onRead(int64(n))
	}
	return n, err
}

func isHopHeader(header string) bool {
	header = strings.ToLower(header)
	for _, h := range hopHeaders {
		if strings.EqualFold(header, h) {
			return true
		}
	}
	return false
}
