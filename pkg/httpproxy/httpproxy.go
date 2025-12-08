package httpproxy

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/ryanbekhen/nanoproxy/pkg/credential"
	"github.com/ryanbekhen/nanoproxy/pkg/resolver"
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

func (s *Server) authenticateRequest(r *http.Request) bool {
	if s.config.Credentials == nil {
		return true
	}

	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		return false
	}

	if strings.HasPrefix(authHeader, "Basic ") {
		encodedCreds := strings.TrimPrefix(authHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encodedCreds)
		if err != nil {
			return false
		}

		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return false
		}

		username, password := parts[0], parts[1]
		return s.config.Credentials.Valid(username, password)
	}

	return false
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateRequest(r) {
		s.config.Logger.Error().
			Str("client_addr", r.RemoteAddr).
			Msg("Unauthorized CONNECT request")
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Restricted area\"")
		http.Error(w, "Proxy authentication required or unauthorized", http.StatusProxyAuthRequired)
		return
	}
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

	go func() {
		_, _ = io.Copy(serverConn, clientConn)
	}()
	_, _ = io.Copy(clientConn, serverConn)
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateRequest(r) {
		s.config.Logger.Error().
			Str("client_addr", r.RemoteAddr).
			Msg("Unauthorized HTTP request")
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Restricted area\"")
		http.Error(w, "Proxy authentication required or unauthorized", http.StatusProxyAuthRequired)
		return
	}

	startTime := time.Now()
	clientIP := r.RemoteAddr

	if !strings.HasPrefix(r.URL.Scheme, "http") {
		s.config.Logger.Error().
			Str("client_addr", clientIP).
			Str("dest_addr", r.URL.String()).
			Msg("Invalid URL scheme")
		http.Error(w, "Invalid URL scheme", http.StatusBadRequest)
		return
	}

	proxyReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		latency := time.Since(startTime).Milliseconds()
		s.config.Logger.Error().
			Str("client_addr", clientIP).
			Str("dest_addr", r.URL.String()).
			Str("latency", fmt.Sprintf("%dms", latency)).
			Msg("Failed to create request - Internal Server Error")
		http.Error(w, "Internal server error while creating request", http.StatusInternalServerError)
		return
	}

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
	resp, err := client.Do(proxyReq)
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
	_, _ = io.Copy(w, resp.Body)
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
