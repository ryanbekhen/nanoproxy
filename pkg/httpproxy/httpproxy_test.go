package httpproxy

import (
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Mock implementation of credential.Store
type mockCredentialStore struct {
	mock.Mock
}

func (m *mockCredentialStore) Valid(username, password string) bool {
	args := m.Called(username, password)
	return args.Bool(0)
}

// Mock resolver implementation for tests
type mockResolver struct{}

func (m *mockResolver) Resolve(hostname string) (net.IP, error) {
	// Handle localhost for testing purposes
	if strings.Contains(hostname, "127.0.0.1") {
		return net.ParseIP("127.0.0.1"), nil
	}
	return nil, fmt.Errorf("failed to resolve %s", hostname)
}

func TestHTTPProxy_ValidCredentials(t *testing.T) {
	// Create a mock credential store
	mockCredStore := &mockCredentialStore{}
	mockCredStore.On("Valid", "testuser", "testpassword").Return(true)

	// Fixed resolver
	mockResolver := &mockResolver{}

	// Configure the proxy server
	proxy := New(&Config{
		Credentials:       mockCredStore,
		Resolver:          mockResolver,
		DestConnTimeout:   5 * time.Second,
		ClientConnTimeout: 5 * time.Second,
	})

	// Create target server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Target Server OK"))
	}))
	defer targetServer.Close()

	// Create a request
	req, err := http.NewRequest(http.MethodGet, targetServer.URL, nil)
	assert.NoError(t, err)

	// Add valid Proxy-Authorization header
	authHeader := base64.StdEncoding.EncodeToString([]byte("testuser:testpassword"))
	req.Header.Set("Proxy-Authorization", "Basic "+authHeader)

	rr := httptest.NewRecorder()

	// Call the proxy
	proxy.ServeHTTP(rr, req)

	// Assert proper behavior
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "Target Server OK", rr.Body.String())

	mockCredStore.AssertExpectations(t)
}

func TestHTTPProxy_InvalidCredentials(t *testing.T) {
	// Create a mock credential store
	mockCredStore := &mockCredentialStore{}
	mockCredStore.On("Valid", "invaliduser", "invalidpassword").Return(false)

	// Fixed resolver
	mockResolver := &mockResolver{}

	// Configure the proxy server
	proxy := New(&Config{
		Credentials:       mockCredStore,
		Resolver:          mockResolver,
		DestConnTimeout:   5 * time.Second,
		ClientConnTimeout: 5 * time.Second,
	})

	// Create target server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Target Server OK"))
	}))
	defer targetServer.Close()

	// Create a request
	req, err := http.NewRequest(http.MethodGet, targetServer.URL, nil)
	assert.NoError(t, err)

	// Add invalid Proxy-Authorization header
	authHeader := base64.StdEncoding.EncodeToString([]byte("invaliduser:invalidpassword"))
	req.Header.Set("Proxy-Authorization", "Basic "+authHeader)

	rr := httptest.NewRecorder()

	// Call the proxy
	proxy.ServeHTTP(rr, req)

	// Assert proxy responds with 407
	assert.Equal(t, http.StatusProxyAuthRequired, rr.Code)

	mockCredStore.AssertExpectations(t)
}

func TestHTTPProxy_NoCredentialsProvided(t *testing.T) {
	// Fixed resolver
	mockResolver := &mockResolver{}

	// Configure the proxy server without credentials
	proxy := New(&Config{
		Credentials:       nil, // No auth required
		Resolver:          mockResolver,
		DestConnTimeout:   5 * time.Second,
		ClientConnTimeout: 5 * time.Second,
	})

	// Create target server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Target Server OK"))
	}))
	defer targetServer.Close()

	// Create a request
	req, err := http.NewRequest(http.MethodGet, targetServer.URL, nil)
	assert.NoError(t, err)

	// No Proxy-Authorization header added
	rr := httptest.NewRecorder()

	// Call the proxy
	proxy.ServeHTTP(rr, req)

	// Assert proxy responds with success
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "Target Server OK", rr.Body.String())
}

func TestHTTPProxy_WithoutAuth_WhenAuthDisabled(t *testing.T) {
	// Fixed resolver
	mockResolver := &mockResolver{}

	// Configure the proxy server without credentials
	proxy := New(&Config{
		Credentials:       nil, // No auth required
		Resolver:          mockResolver,
		DestConnTimeout:   5 * time.Second,
		ClientConnTimeout: 5 * time.Second,
	})

	// Create target server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("No Auth Required"))
	}))
	defer targetServer.Close()

	// Create a request
	req, err := http.NewRequest(http.MethodGet, targetServer.URL, nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()

	// Call the proxy
	proxy.ServeHTTP(rr, req)

	// Assert proxy responds with success
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "No Auth Required", rr.Body.String())
}
