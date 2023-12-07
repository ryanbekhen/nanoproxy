package socks5

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"net"
	"os"
	"strings"
	"time"
)

type Config struct {
	Authentication    []Authenticator
	Credentials       CredentialStore
	Logger            *zerolog.Logger
	DestConnTimeout   time.Duration
	ClientConnTimeout time.Duration
	Dial              func(network, addr string) (net.Conn, error)
	AfterRequest      func(req *Request, conn net.Conn)
	Resolver          Resolver
	Rewriter          AddressRewriter
}

type Server struct {
	config         *Config
	authentication map[AuthType]Authenticator
	listener       net.Listener
}

func New(conf *Config) *Server {
	if len(conf.Authentication) == 0 {
		if conf.Credentials != nil {
			conf.Authentication = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.Authentication = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	if conf.Logger == nil {
		logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Timestamp().Logger()
		conf.Logger = &logger
	}

	if conf.Resolver == nil {
		conf.Resolver = &DNSResolver{}
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

	server.authentication = make(map[AuthType]Authenticator)

	for _, a := range conf.Authentication {
		server.authentication[a.GetCode()] = a
	}

	return server
}

func (s *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.serve(l)
}

func (s *Server) Shutdown() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) serve(l net.Listener) error {
	s.listener = l
	for {
		conn, err := l.Accept()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return err
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer func(conn net.Conn) {
		if err := conn.Close(); err != nil {
			s.config.Logger.Error().Err(err).Msg("failed to close connection")
		}
	}(conn)
	connectionBuffer := bufio.NewReader(conn)

	// Set a deadline for the connection
	if err := conn.SetDeadline(time.Now().Add(s.config.ClientConnTimeout)); err != nil {
		s.config.Logger.Err(err).Msg("failed to set connection deadline")
		return
	}

	// Read the version byte
	version := []byte{0}
	if _, err := connectionBuffer.Read(version); err != nil {
		s.config.Logger.Err(err).Msg("failed to read version byte")
		return
	}

	// Ensure we are compatible
	if version[0] != Version {
		s.config.Logger.Error().Msg("unsupported version")
		return
	}

	// Authenticate
	authContext, err := s.authenticate(conn, connectionBuffer)
	if err != nil {
		s.config.Logger.Err(err).Msg("failed to authenticate")
		return
	}

	request, err := NewRequest(connectionBuffer)
	if err != nil {
		if errors.Is(err, ErrUnrecognizedAddrType) {
			if err := sendReply(conn, StatusAddressNotSupported.Uint8(), nil); err != nil {
				s.config.Logger.Err(err).Msg("failed to send reply")
				return
			}
		}
		s.config.Logger.Err(err).Msg("failed to create request")
		return
	}
	request.AuthContext = authContext

	if clientAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: clientAddr.IP, Port: clientAddr.Port}
	}

	if err := s.handleRequest(request, conn); err != nil &&
		!strings.Contains(err.Error(), "i/o timeout") {
		s.config.Logger.Err(err).
			Msg("request failed")
	} else {
		s.config.Logger.Info().
			Str("client_addr", conn.RemoteAddr().String()).
			Str("dest_addr", request.DestAddr.String()).
			Str("latency", request.Latency.String()).
			Msg("request completed")
	}

	if s.config.AfterRequest != nil {
		s.config.AfterRequest(request, conn)
	}
}

func (s *Server) authenticate(conn net.Conn, bufConn *bufio.Reader) (*AuthContext, error) {
	// Get the methods
	methods, err := readMethods(bufConn)
	if err != nil {
		return nil, fmt.Errorf("failed to read methods: %w", err)
	}

	// Select a usable method
	for _, method := range methods {
		if auth, ok := s.authentication[AuthType(method)]; ok {
			return auth.Authenticate(bufConn, conn)
		}
	}

	// No usable method found
	return nil, noAcceptable(conn)
}

func (s *Server) handleRequest(req *Request, conn net.Conn) error {
	dest := req.DestAddr
	if dest.FQDN != "" {
		addr, err := s.config.Resolver.Resolve(dest.FQDN)
		if err != nil {
			if err := sendReply(conn, StatusHostUnreachable.Uint8(), nil); err != nil {
				return ErrFailedToSendReply
			}
			return fmt.Errorf("failed to resolve destination: %w", err)
		}
		dest.IP = addr
	}

	req.realAddr = req.DestAddr
	if s.config.Rewriter != nil {
		req.realAddr = s.config.Rewriter.Rewrite(req)
	}

	switch req.Command {
	case CommandConnect:
		return s.handleConnect(conn, req)
	// TODO: Implement these
	//case CommandBind:
	//	return s.handleBind(conn, req)
	//case CommandAssociate:
	//	return s.handleAssociate(conn, req)
	default:
		if err := sendReply(conn, StatusCommandNotSupported.Uint8(), nil); err != nil {
			return ErrFailedToSendReply
		}
		return fmt.Errorf("unsupported command: %d", req.Command)
	}
}

func (s *Server) handleConnect(conn net.Conn, req *Request) error {
	dial := s.config.Dial
	if dial == nil {
		dial = func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, s.config.DestConnTimeout)
		}
	}

	processStartTimestamp := time.Now()
	dest, err := dial("tcp", req.realAddr.Address())
	req.Latency = time.Since(processStartTimestamp)

	if err != nil {
		msg := err.Error()
		resp := StatusHostUnreachable
		if strings.Contains(msg, "refused") {
			resp = StatusConnectionRefused
			msg = "connection refused " + req.DestAddr.IP.String()
		}

		if strings.Contains(msg, "unreachable network") {
			resp = StatusNetworkUnreachable
			msg = "unreachable network " + req.DestAddr.IP.String()
		}

		if err := sendReply(conn, resp.Uint8(), nil); err != nil {
			return ErrFailedToSendReply
		}

		return errors.New(msg)
	}
	defer func() {
		_ = dest.Close()
	}()

	local := dest.LocalAddr().(*net.TCPAddr)
	bind := AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(conn, StatusRequestGranted.Uint8(), &bind); err != nil {
		return ErrFailedToSendReply
	}

	errChan := make(chan error, 2)
	go relay(dest, req.BufferConn, errChan)
	go relay(conn, dest, errChan)

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			return err
		}
	}

	return nil
}
