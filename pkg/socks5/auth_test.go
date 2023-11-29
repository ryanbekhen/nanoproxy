package socks5

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

type mockCredentialStore struct {
	valid bool
}

func (m *mockCredentialStore) Valid(user, password string) bool {
	return m.valid
}

type errorWriter struct{}

func (e *errorWriter) Write(p []byte) (n int, err error) {
	return 0, assert.AnError
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, assert.AnError
}

func TestNoAuthAuthenticator(t *testing.T) {
	auth := &NoAuthAuthenticator{}
	reader := bytes.NewBuffer(nil)
	writer := bytes.NewBuffer(nil)

	_, err := auth.Authenticate(reader, writer)
	assert.NoError(t, err)

	expected := []byte{Version, uint8(NoAuth)}
	assert.Equal(t, expected, writer.Bytes())
	assert.Equal(t, NoAuth, auth.GetCode())
}

func TestUserPassAuthenticator(t *testing.T) {
	auth := &UserPassAuthenticator{
		Credentials: &mockCredentialStore{valid: true},
	}
	reader := bytes.NewBuffer([]byte{UserAuthVersion, 4, 'u', 's', 'e', 'r', 3, 'p', 'a', 's', 's'})
	writer := bytes.NewBuffer(nil)

	_, err := auth.Authenticate(reader, writer)
	assert.NoError(t, err)

	expected := []byte{Version, uint8(UserPassAuth), UserAuthVersion, uint8(AuthSuccess)}
	assert.Equal(t, expected, writer.Bytes())
	assert.Equal(t, UserPassAuth, auth.GetCode())
}

func TestUserPassAuthenticator_Authenticate(t *testing.T) {
	auth := &UserPassAuthenticator{
		Credentials: &mockCredentialStore{valid: false},
	}
	reader := bytes.NewBuffer([]byte{UserAuthVersion, 4, 'u', 's', 'e', 'r', 3, 'p', 'a', 's', 's'})
	writer := bytes.NewBuffer(nil)

	_, err := auth.Authenticate(reader, writer)
	assert.Equal(t, "invalid credentials", err.Error())

	expected := []byte{Version, uint8(UserPassAuth), UserAuthVersion, uint8(AuthFailure)}
	assert.Equal(t, expected, writer.Bytes())
}

func TestUserPassAuthenticator_Authenticate_InvalidVersion(t *testing.T) {
	auth := &UserPassAuthenticator{
		Credentials: &mockCredentialStore{valid: true},
	}
	reader := bytes.NewBuffer([]byte{0, 4, 'u', 's', 'e', 'r', 3, 'p', 'a', 's', 's'})
	writer := bytes.NewBuffer(nil)

	_, err := auth.Authenticate(reader, writer)
	assert.Equal(t, "unsupported authentication version: 0", err.Error())

	expected := []byte{Version, uint8(UserPassAuth)}
	assert.Equal(t, expected, writer.Bytes())
}

func TestUserPassAuthenticator_Authenticate_InvalidUser(t *testing.T) {
	auth := &UserPassAuthenticator{
		Credentials: &mockCredentialStore{valid: true},
	}
	reader := bytes.NewBuffer([]byte{UserAuthVersion, 4, 'u', 's', 'e', 'r', 3, 'p', 'a', 's', 's'})
	writer := bytes.NewBuffer(nil)

	_, err := auth.Authenticate(reader, writer)
	assert.NoError(t, err)

	expected := []byte{Version, uint8(UserPassAuth), UserAuthVersion, uint8(AuthSuccess)}
	assert.Equal(t, expected, writer.Bytes())
}

func TestUserPassAuthenticator_Authenticate_InvalidPassword(t *testing.T) {
	auth := &UserPassAuthenticator{
		Credentials: &mockCredentialStore{valid: true},
	}
	reader := bytes.NewBuffer([]byte{UserAuthVersion, 4, 'u', 's', 'e', 'r', 3, 'p', 'a', 's', 's'})
	writer := bytes.NewBuffer(nil)

	_, err := auth.Authenticate(reader, writer)
	assert.NoError(t, err)

	expected := []byte{Version, uint8(UserPassAuth), UserAuthVersion, uint8(AuthSuccess)}
	assert.Equal(t, expected, writer.Bytes())
}

func TestUserPassAuthenticator_Authenticate_Error(t *testing.T) {
	auth := &UserPassAuthenticator{
		Credentials: &mockCredentialStore{valid: true},
	}
	reader := bytes.NewBuffer([]byte{UserAuthVersion, 4, 'u', 's', 'e', 'r', 3, 'p', 'a', 's', 's'})
	writer := &errorWriter{}

	_, err := auth.Authenticate(reader, writer)
	assert.Error(t, err)
}

func TestUserPassAuthenticator_Authenticate_ErrorReadVersion(t *testing.T) {
	auth := &UserPassAuthenticator{
		Credentials: &mockCredentialStore{valid: true},
	}
	reader := &errorReader{}
	writer := bytes.NewBuffer(nil)

	_, err := auth.Authenticate(reader, writer)
	assert.Error(t, err)
}

func TestUserPassAuthenticator_Authenticate_ErrorReadUsername(t *testing.T) {
	auth := &UserPassAuthenticator{
		Credentials: &mockCredentialStore{valid: true},
	}
	reader := bytes.NewBuffer([]byte{UserAuthVersion, 4})
	writer := bytes.NewBuffer(nil)

	_, err := auth.Authenticate(reader, writer)
	assert.Error(t, err)
}

func TestUserPassAuthenticator_Authenticate_ErrorReadPasswordLength(t *testing.T) {
	auth := &UserPassAuthenticator{
		Credentials: &mockCredentialStore{valid: true},
	}
	reader := bytes.NewBuffer([]byte{UserAuthVersion, 5, 'u', 's', 'e', 'r', 3})
	writer := bytes.NewBuffer(nil)

	_, err := auth.Authenticate(reader, writer)
	assert.Error(t, err)
}

func TestUserPassAuthenticator_Authenticate_ErrorReadPassword(t *testing.T) {
	auth := &UserPassAuthenticator{
		Credentials: &mockCredentialStore{valid: true},
	}
	reader := bytes.NewBuffer([]byte{UserAuthVersion, 4, 'u', 's', 'e', 'r', 3})
	writer := bytes.NewBuffer(nil)

	_, err := auth.Authenticate(reader, writer)
	assert.Error(t, err)
}

func TestReadMethods(t *testing.T) {
	reader := bytes.NewBuffer([]byte{2, 0, 2})
	methods, err := readMethods(reader)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0, 2}, methods)
}

func TestNoAcceptableMethods(t *testing.T) {
	reader := bytes.NewBuffer([]byte{0})
	err := noAcceptable(reader)
	assert.Error(t, err)
}
