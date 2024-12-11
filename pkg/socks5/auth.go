package socks5

import (
	"fmt"
	"github.com/ryanbekhen/nanoproxy/pkg/credential"
	"io"
)

// AuthType is the type of authentication used by the client to connect to the proxy server (see RFC 1928, Section 2)
type AuthType uint8

func (a AuthType) Uint8() uint8 {
	return uint8(a)
}

// AuthStatus is the status of the authentication process
type AuthStatus uint8

func (a AuthStatus) Uint8() uint8 {
	return uint8(a)
}

const (
	NoAuth       AuthType = 0x00
	NoAcceptable AuthType = 0xFF
	UserPassAuth AuthType = 0x02

	AuthSuccess AuthStatus = 0x00
	AuthFailure AuthStatus = 0x01

	UserAuthVersion = 0x01
)

var (
	ErrAuthFailure = fmt.Errorf("authentication failure")
)

// Context encapsulates authentication state provided during negotiation
type Context struct {
	// Method is the provided auth method
	Method AuthType
	// Payload provided during negotiation.
	// Keys depend on the used auth method.
	// For UserPass-auth contains Username
	Payload map[string]string
}

// Authenticator is the interface implemented by types that can handle authentication
type Authenticator interface {
	Authenticate(reader io.Reader, writer io.Writer) (*Context, error)
	GetCode() AuthType
}

// NoAuthAuthenticator is used to handle the "No Authentication" mode
type NoAuthAuthenticator struct{}

// GetCode returns the code of the authenticator
func (a *NoAuthAuthenticator) GetCode() AuthType {
	return NoAuth
}

// Authenticate handles the authentication process
func (a *NoAuthAuthenticator) Authenticate(_ io.Reader, writer io.Writer) (*Context, error) {
	_, err := writer.Write([]byte{Version, uint8(NoAuth)})
	return &Context{NoAuth, nil}, err
}

// UserPassAuthenticator is used to handle username/password-based authentication
type UserPassAuthenticator struct {
	Credentials credential.Store
}

// GetCode returns the code of the authenticator
func (a *UserPassAuthenticator) GetCode() AuthType {
	return UserPassAuth
}

// Authenticate handles the authentication process
func (a *UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer) (*Context, error) {
	if _, err := writer.Write([]byte{Version, uint8(UserPassAuth)}); err != nil {
		return nil, err
	}

	// Read the version byte
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(reader, header, 2); err != nil {
		return nil, err
	}

	// Ensure we are compatible
	if header[0] != UserAuthVersion {
		return nil, fmt.Errorf("unsupported authentication version: %d", header[0])
	}

	// Get the username
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(reader, user, userLen); err != nil {
		return nil, err
	}

	// Get the password length
	if _, err := reader.Read(header[:1]); err != nil {
		return nil, err
	}

	// Get the password
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(reader, pass, passLen); err != nil {
		return nil, err
	}

	// Check the credentials
	if a.Credentials.Valid(string(user), string(pass)) {
		if _, err := writer.Write([]byte{UserAuthVersion, uint8(AuthSuccess)}); err != nil {
			return nil, err
		}
	} else {
		if _, err := writer.Write([]byte{UserAuthVersion, uint8(AuthFailure)}); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("invalid credentials")
	}

	return &Context{UserPassAuth, map[string]string{"Username": string(user)}}, nil
}

func readMethods(bufConn io.Reader) ([]byte, error) {
	header := []byte{0}
	if _, err := bufConn.Read(header); err != nil {
		return nil, err
	}

	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	_, err := io.ReadAtLeast(bufConn, methods, numMethods)

	return methods, err
}

func noAcceptable(conn io.Writer) error {
	_, err := conn.Write([]byte{Version, uint8(NoAcceptable)})
	if err != nil {
		return err
	}
	return fmt.Errorf("no acceptable authentication method")
}
