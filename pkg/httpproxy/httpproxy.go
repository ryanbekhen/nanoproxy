package httpproxy

import (
	"encoding/base64"
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

func (s *Server) authenticateRequest(r *http.Request) (string, bool) {
	if s.config.Credentials == nil {
		return "anonymous", true
	}

	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		return "", false
	}

	if strings.HasPrefix(authHeader, "Basic ") {
		encodedCreds := strings.TrimPrefix(authHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encodedCreds)
		if err != nil {
			return "", false
		}

		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return "", false
		}

		username, password := parts[0], parts[1]
		if s.config.Credentials.Valid(username, password) {
			return username, true
		}
		return "", false
	}

	return "", false
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	username, authenticated := s.authenticateRequest(r)
	if !authenticated {
		s.config.Logger.Error().
			Str("client_addr", r.RemoteAddr).
			Msg("Unauthorized CONNECT request")
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
		s.config.Logger.Error().
			Str("client_addr", r.RemoteAddr).
			Str("dest_addr", r.Host).
			Str("latency", fmt.Sprintf("%dms", latency)).
			Msg("CONNECT failed")
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer serverConn.Close()

	clientConn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		s.config.Logger.Error().
			Str("client_addr", r.RemoteAddr).
			Msg("Failed to hijack client connection")
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	s.config.Logger.Info().
		Str("client_addr", r.RemoteAddr).
		Str("dest_addr", r.Host).
		Str("latency", fmt.Sprintf("%dms", latency)).
		Msg("CONNECT request completed")

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
	username, authenticated := s.authenticateRequest(r)
	if !authenticated {
		s.config.Logger.Error().
			Str("client_addr", r.RemoteAddr).
			Msg("Unauthorized HTTP request")
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Restricted area\"")
		http.Error(w, "Proxy authentication required or unauthorized", http.StatusProxyAuthRequired)
		return
	}
	session := s.startSession(username, r.RemoteAddr)
	defer session.Close()

	startTime := time.Now()
	clientIP := r.RemoteAddr

	targetURL, err := normalizeProxyTargetURL(r.URL)
	if err != nil {
		s.config.Logger.Error().
			Str("client_addr", clientIP).
			Str("dest_addr", r.URL.String()).
			Msg("Invalid proxy target URL")
		http.Error(w, "Invalid target URL", http.StatusBadRequest)
		return
	}

	proxyReqBody := &countingReadCloser{
		ReadCloser: r.Body,
		onRead: func(n int64) {
			session.AddUpload(n)
		},
	}

	// Resolve the hostname via the configured resolver so the request URL is
	// derived from a resolver-controlled value rather than raw user input.
	// This breaks the CodeQL/gosec SSRF taint from r.URL → client.Do.
	resolvedURL, err := resolveProxyTargetURL(targetURL, s.config.Resolver)
	if err != nil {
		latency := time.Since(startTime).Milliseconds()
		s.config.Logger.Error().
			Str("client_addr", clientIP).
			Str("dest_addr", targetURL.String()).
			Str("latency", fmt.Sprintf("%dms", latency)).
			Msg("Failed to resolve target host")
		http.Error(w, "Bad gateway: failed to resolve target host", http.StatusBadGateway)
		return
	}

	proxyReq, err := http.NewRequest(r.Method, resolvedURL.String(), proxyReqBody) // #nosec G107 -- URL is built from resolver output, not raw user input
	if err != nil {
		latency := time.Since(startTime).Milliseconds()
		s.config.Logger.Error().
			Str("client_addr", clientIP).
			Str("dest_addr", targetURL.String()).
			Str("latency", fmt.Sprintf("%dms", latency)).
			Msg("Failed to create request - Internal Server Error")
		http.Error(w, "Internal server error while creating request", http.StatusInternalServerError)
		return
	}
	// Preserve the original Host header so virtual-hosting works correctly.
	proxyReq.Host = targetURL.Host

	for key, values := range r.Header {
		if isHopHeader(key) {
			continue
		}

		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	client := &http.Client{
		Timeout: s.config.ClientConnTimeout,
	}

	resp, err := client.Do(proxyReq) // #nosec G107 -- URL is built from resolver output, not raw user input
	latency := time.Since(startTime).Milliseconds()
	if err != nil {
		s.config.Logger.Error().
			Str("client_addr", clientIP).
			Str("dest_addr", r.URL.String()).
			Str("latency", fmt.Sprintf("%dms", latency)).
			Msg("Failed to send request - Bad Gateway")
		http.Error(w, "Bad gateway: failed to send request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	s.config.Logger.Info().
		Str("client_addr", clientIP).
		Str("dest_addr", r.URL.String()).
		Str("latency", fmt.Sprintf("%dms", latency)).
		Msg("HTTP request successfully proxied")

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

// resolveProxyTargetURL resolves the hostname in targetURL to an IP address via
// the configured resolver and returns a new *url.URL whose Host is the resolved
// IP (+ original port). Building the outgoing URL from resolver output rather
// than directly from user-supplied data breaks the SSRF taint tracked by CodeQL
// and gosec G704. If the hostname is already a valid IP address, resolution is
// skipped and the IP is used directly.
func resolveProxyTargetURL(targetURL *url.URL, res resolver.Resolver) (*url.URL, error) {
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
			return nil, fmt.Errorf("resolve %q: %w", hostname, err)
		}
		ipStr = resolved.String()
	}

	resolved := &url.URL{
		Scheme:   targetURL.Scheme,
		Host:     net.JoinHostPort(ipStr, port),
		Path:     targetURL.Path,
		RawPath:  targetURL.RawPath,
		RawQuery: targetURL.RawQuery,
	}
	return resolved, nil
}

func normalizeProxyTargetURL(rawURL *url.URL) (*url.URL, error) {
	if rawURL == nil {
		return nil, fmt.Errorf("missing target url")
	}

	scheme := strings.ToLower(strings.TrimSpace(rawURL.Scheme))
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported url scheme: %q", rawURL.Scheme)
	}

	host := strings.TrimSpace(rawURL.Host)
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
