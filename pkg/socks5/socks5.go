package socks5

import (
	"bufio"
	"errors"
	"github.com/rs/zerolog"
	"net"
	"os"
	"time"

	"context"
)

const (
	socks5Version = uint8(5)
)

// Config is used to set up and configure a Server
type Config struct {
	// AuthMethods can be provided to implement custom authentication
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	AuthMethods []Authenticator

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AUthMethods is a nil, then "auth-less" mode is enabled.
	Credentials CredentialStore

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	Rules RuleSet

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter AddressRewriter

	// BindIP is used for bind or udp associate
	BindIP net.IP

	// Logger can be used to provide a custom log target.
	// Defaults to stdout.
	Logger *zerolog.Logger

	// Optional function for dialing out
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config      *Config
	authMethods map[uint8]Authenticator
}

// New creates a new Server and potentially returns an error
func New(conf *Config) (*Server, error) {
	// Ensure we have at least one authentication method enabled
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	// Ensure we have a DNS resolver
	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	// Ensure we have a rule set
	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}

	// Ensure we have a log target
	if conf.Logger == nil {
		logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Timestamp().Logger()
		conf.Logger = &logger
	}

	server := &Server{
		config: conf,
	}

	server.authMethods = make(map[uint8]Authenticator)

	for _, a := range conf.AuthMethods {
		server.authMethods[a.GetCode()] = a
	}

	return server, nil
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(conn)
	}
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(conn net.Conn) {
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			s.config.Logger.Err(err).Msg("failed to close connection")
		}
	}(conn)
	bufConn := bufio.NewReader(conn)

	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		s.config.Logger.Err(err).Msg("failed to get version byte")
		return
	}

	// Ensure we are compatible
	if version[0] != socks5Version {
		s.config.Logger.Error().Msgf("unsupported SOCKS version: %v", version)
		return
	}

	// Authenticate the connection
	authContext, err := s.authenticate(conn, bufConn)
	if err != nil {
		s.config.Logger.Err(err).Msg("failed to authenticate")
		return
	}

	request, err := NewRequest(bufConn)
	if err != nil {
		if errors.Is(err, unrecognizedAddrType) {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				s.config.Logger.Err(err).Msg("failed to send reply")
				return
			}
		}
		s.config.Logger.Err(err).Msg("failed to read destination address")
		return
	}
	request.AuthContext = authContext
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}

	// Process the client request
	if err := s.handleRequest(request, conn); err != nil {
		s.config.Logger.Err(err).Msg("failed to handle request")
	}

	s.config.Logger.Info().
		Str("remote_addr", conn.RemoteAddr().String()).
		Str("command", parseCommand(request.Command)).
		Str("dest_addr", request.DestAddr.String()).
		Str("latency", request.Latency.String()).
		Msg("request processed")
}
