package httpproxy

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type MockCredentialStore struct{}

func (m *MockCredentialStore) Add(username, password string) {

}

func (m *MockCredentialStore) Valid(username, password string) bool {
	return username == "user" && password == "password"
}

type MockResolver struct{}

func (m *MockResolver) Resolve(host string) (net.IP, error) {
	if host == "validhost.com" {
		return net.ParseIP("127.0.0.1"), nil
	}
	return nil, errors.New("host not found")
}

type MockNetConn struct{}

func (m *MockNetConn) Read(b []byte) (n int, err error) {
	return 0, io.EOF
}

func (m *MockNetConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *MockNetConn) Close() error {
	return nil
}

func (m *MockNetConn) LocalAddr() net.Addr                { return nil }
func (m *MockNetConn) RemoteAddr() net.Addr               { return nil }
func (m *MockNetConn) SetDeadline(t time.Time) error      { return nil }
func (m *MockNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *MockNetConn) SetWriteDeadline(t time.Time) error { return nil }

type MockHijacker struct {
	*httptest.ResponseRecorder
}

func (m *MockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	mockConn := &MockNetConn{}
	buf := bufio.NewReadWriter(bufio.NewReader(mockConn), bufio.NewWriter(mockConn))
	return mockConn, buf, nil
}

func TestServer_ServeHTTP(t *testing.T) {
	logger := zerolog.New(io.Discard)
	mockCredentials := &MockCredentialStore{}
	mockResolver := &MockResolver{}

	server := New(&Config{
		Credentials:       mockCredentials,
		Logger:            &logger,
		DestConnTimeout:   2 * time.Second,
		ClientConnTimeout: 2 * time.Second,
		Dial: func(network, addr string) (net.Conn, error) {
			return &MockNetConn{}, nil
		},
		Resolver: mockResolver,
	})

	t.Run("Handle HTTP - unauthorized request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
		rr := httptest.NewRecorder()

		server.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusProxyAuthRequired, rr.Code)
		assert.Contains(t, rr.Body.String(), "Proxy authentication required")
	})

	t.Run("Handle HTTP - successful authorization but Dial fails", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:password")))
		rr := httptest.NewRecorder()

		server.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadGateway, rr.Code)
	})

	t.Run("Handle HTTP - failed to resolve host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://invalidhostinvalidhostinvalidhost.com", nil)
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:password")))
		rr := httptest.NewRecorder()

		server.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadGateway, rr.Code)
		assert.Contains(t, rr.Body.String(), "Bad gateway: failed to send request")
	})
}

func TestServer_HandleCONNECT(t *testing.T) {
	logger := zerolog.New(io.Discard)
	mockCredentials := &MockCredentialStore{}

	server := New(&Config{
		Credentials:       mockCredentials,
		Logger:            &logger,
		DestConnTimeout:   2 * time.Second,
		ClientConnTimeout: 2 * time.Second,
		Dial: func(network, addr string) (net.Conn, error) {
			return &MockNetConn{}, nil
		},
	})

	t.Run("Handle CONNECT - unauthorized request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodConnect, "http://example.com", nil)
		rr := httptest.NewRecorder()

		server.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusProxyAuthRequired, rr.Code)
		assert.Contains(t, rr.Body.String(), "Proxy authentication required")
	})

	t.Run("Handle CONNECT - successful connection", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:password")))
		rr := httptest.NewRecorder()

		hj := &MockHijacker{ResponseRecorder: rr}
		done := make(chan bool, 1)

		go func() {
			defer close(done)
			server.ServeHTTP(hj, req)
			done <- true
		}()

		select {
		case <-done:
			assert.Equal(t, http.StatusOK, rr.Code)
		case <-time.After(5 * time.Second):
			t.Fatal("Test timeout after 5 seconds")
		}
	})
}

func TestProxy_ForwardRequests(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Connection"))
		assert.Empty(t, r.Header.Get("Keep-Alive"))
		w.Header().Set("X-Test-Header", "TestValue")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Target server response"))
	}))
	defer targetServer.Close()

	logger := zerolog.New(io.Discard)

	server := New(&Config{
		Logger:            &logger,
		ClientConnTimeout: 2 * time.Second,
	})

	proxy := httptest.NewServer(server)
	defer proxy.Close()

	t.Run("Successful forward request", func(t *testing.T) {
		client := &http.Client{Timeout: 2 * time.Second}
		req, _ := http.NewRequest(http.MethodGet, targetServer.URL, nil)

		resp, err := client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		defer resp.Body.Close()

		assert.Equal(t, "Target server response", string(body))
	})
}

func TestServer_HandleHTTP_WithProxyRequest(t *testing.T) {
	targetURL := "http://httpbin.org"
	logger := zerolog.New(io.Discard)

	proxy := New(&Config{
		Credentials:       &MockCredentialStore{},
		Logger:            &logger,
		DestConnTimeout:   2 * time.Second,
		ClientConnTimeout: 2 * time.Second,
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial(network, addr)
		},
	})
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	t.Run("Forward HTTP request successfully", func(t *testing.T) {
		clientReq, err := http.NewRequest(http.MethodGet, targetURL+"/anything", nil)
		if err != nil {
			t.Fatalf("Gagal membuat request: %v", err)
		}

		clientReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:password")))
		clientReq.Header.Set("X-Custom-Header", "TestValue")
		clientReq.Header.Set("X-Backend-Response", "Success")

		proxyClient := &http.Client{
			Transport: &http.Transport{
				Proxy: func(req *http.Request) (*url.URL, error) {
					return url.Parse(proxyServer.URL)
				},
			},
			Timeout: 2 * time.Second,
		}

		resp, err := proxyClient.Do(clientReq)
		assert.NoError(t, err)
		if err != nil {
			t.Fatalf("[ERROR] Proxy client mengalami error: %v", err)
		}

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		defer resp.Body.Close()

		var responseJSON map[string]interface{}
		err = json.Unmarshal(body, &responseJSON)
		assert.NoError(t, err)

		headers := responseJSON["headers"].(map[string]interface{})

		expectedBackendResponse := "Success"
		actualBackendResponse := headers["X-Backend-Response"]
		assert.Equal(t, expectedBackendResponse, actualBackendResponse)

		expectedCustomHeader := "TestValue"
		actualCustomHeader := headers["X-Custom-Header"]
		assert.Equal(t, expectedCustomHeader, actualCustomHeader)
	})
}

func TestServer_HandleHTTP_InvalidURLScheme(t *testing.T) {
	logger := zerolog.New(io.Discard)

	server := New(&Config{
		Logger:            &logger,
		ClientConnTimeout: 2 * time.Second,
	})

	t.Run("Invalid URL Scheme", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "ftp://example.com", nil) // Skema tidak valid (ftp)
		rr := httptest.NewRecorder()

		server.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)            // Memastikan statusnya Bad Request
		assert.Contains(t, rr.Body.String(), "Invalid URL scheme") // Memastikan pesan error sesuai
	})
}

func TestServer_HandleHTTP_ClientDoError(t *testing.T) {
	logger := zerolog.New(io.Discard)

	server := New(&Config{
		Logger:            &logger,
		ClientConnTimeout: 2 * time.Second,
	})

	t.Run("Failed to resolve DNS", func(t *testing.T) {
		// Membuat permintaan HTTP Proxy
		proxyReq := httptest.NewRequest(http.MethodGet, "http://unreachablehost", nil)
		proxyReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:password")))

		rr := httptest.NewRecorder()

		server.ServeHTTP(rr, proxyReq)

		// Kode status harus 502: Bad Gateway karena resolve gagal
		assert.Equal(t, http.StatusBadGateway, rr.Code)

		// Validasi pesan error
		assert.Contains(t, rr.Body.String(), "Bad gateway: failed to resolve destination")
	})
}
