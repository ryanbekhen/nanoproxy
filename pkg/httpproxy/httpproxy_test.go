package httpproxy

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
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

type resolverFunc func(host string) (net.IP, error)

func (f resolverFunc) Resolve(host string) (net.IP, error) {
	return f(host)
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

type writeFailConn struct{}

func (c *writeFailConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (c *writeFailConn) Write(_ []byte) (int, error)        { return 0, errors.New("write failed") }
func (c *writeFailConn) Close() error                       { return nil }
func (c *writeFailConn) LocalAddr() net.Addr                { return nil }
func (c *writeFailConn) RemoteAddr() net.Addr               { return nil }
func (c *writeFailConn) SetDeadline(_ time.Time) error      { return nil }
func (c *writeFailConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *writeFailConn) SetWriteDeadline(_ time.Time) error { return nil }

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

	t.Run("Handle HTTP - successful authorization but backend unreachable", func(t *testing.T) {
		// Create a local backend server and immediately close it to simulate unreachable target
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		backendURL := backend.URL
		backend.Close()

		req := httptest.NewRequest(http.MethodGet, backendURL, nil)
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
		assert.Contains(t, rr.Body.String(), "Bad gateway: failed to resolve target host")
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
	// Local echo server to avoid hitting public URLs
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		headers := map[string]string{}
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"headers": headers,
		})
	}))
	defer echoServer.Close()

	targetURL := echoServer.URL
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
			t.Fatalf("failed to create request: %v", err)
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
			t.Fatalf("proxy client returned an error: %v", err)
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
		req := httptest.NewRequest(http.MethodGet, "ftp://example.com", nil) // Invalid scheme (ftp)
		rr := httptest.NewRecorder()

		server.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)            // Verify the response status is Bad Request.
		assert.Contains(t, rr.Body.String(), "Invalid target URL") // Verify the expected error message.
	})
}

func TestServer_HandleHTTP_ClientDoError(t *testing.T) {
	logger := zerolog.New(io.Discard)

	server := New(&Config{
		Logger:            &logger,
		ClientConnTimeout: 2 * time.Second,
	})

	t.Run("Failed to resolve DNS", func(t *testing.T) {
		// Create a proxied HTTP request.
		proxyReq := httptest.NewRequest(http.MethodGet, "http://unreachablehost", nil)
		proxyReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:password")))

		rr := httptest.NewRecorder()

		server.ServeHTTP(rr, proxyReq)

		assert.Equal(t, http.StatusBadGateway, rr.Code)
		assert.Contains(t, rr.Body.String(), "Bad gateway: failed to resolve target host")
	})
}

func TestNormalizeProxyTargetURL(t *testing.T) {
	t.Run("Rejects nil request", func(t *testing.T) {
		_, err := normalizeProxyTargetURL(nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing target url")
	})

	t.Run("Rejects missing host", func(t *testing.T) {
		req := &http.Request{URL: &url.URL{Scheme: "http", Path: "/"}}

		_, err := normalizeProxyTargetURL(req)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing url host")
	})

	t.Run("Uses request host when URL host is empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://placeholder", nil)
		req.URL.Host = ""
		req.URL.Path = "/status"
		req.URL.RawQuery = "check=1"
		req.Host = "example.com:8080"

		targetURL, err := normalizeProxyTargetURL(req)

		assert.NoError(t, err)
		assert.Equal(t, "http", targetURL.Scheme)
		assert.Equal(t, "example.com:8080", targetURL.Host)
		assert.Equal(t, "/status", targetURL.Path)
		assert.Equal(t, "check=1", targetURL.RawQuery)
	})

	t.Run("Rejects userinfo", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://user:pass@example.com/private", nil)

		_, err := normalizeProxyTargetURL(req)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "userinfo")
	})
}

func TestDialProxyTarget(t *testing.T) {
	t.Run("Returns plain TCP conn for HTTP", func(t *testing.T) {
		fakeConn := &MockNetConn{}

		conn, err := dialProxyTarget(&url.URL{Scheme: "http", Host: "example.com"}, "127.0.0.1:80", func(network, addr string) (net.Conn, error) {
			assert.Equal(t, "tcp", network)
			assert.Equal(t, "127.0.0.1:80", addr)
			return fakeConn, nil
		}, time.Second)

		assert.NoError(t, err)
		assert.Same(t, fakeConn, conn)
	})

	t.Run("Returns handshake error for HTTPS", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer serverConn.Close()

		go func() {
			// Trigger TLS handshake failure on client side.
			_, _ = serverConn.Write([]byte("not-tls"))
			_ = serverConn.Close()
		}()

		_, err := dialProxyTarget(&url.URL{Scheme: "https", Host: "example.com"}, "127.0.0.1:443", func(network, addr string) (net.Conn, error) {
			return clientConn, nil
		}, time.Second)

		assert.Error(t, err)
	})
}

func TestResolveProxyTargetAddr(t *testing.T) {
	t.Run("Uses resolver result with default HTTPS port", func(t *testing.T) {
		targetURL := &url.URL{Scheme: "https", Host: "validhost.com"}

		addr, err := resolveProxyTargetAddr(targetURL, resolverFunc(func(host string) (net.IP, error) {
			assert.Equal(t, "validhost.com", host)
			return net.ParseIP("203.0.113.10"), nil
		}))

		assert.NoError(t, err)
		assert.Equal(t, "203.0.113.10:443", addr)
	})

	t.Run("Keeps literal IP addresses without DNS lookup", func(t *testing.T) {
		targetURL := &url.URL{Scheme: "http", Host: "127.0.0.1:9000"}

		addr, err := resolveProxyTargetAddr(targetURL, resolverFunc(func(host string) (net.IP, error) {
			t.Fatalf("resolver should not be called for literal IPs")
			return nil, nil
		}))

		assert.NoError(t, err)
		assert.Equal(t, "127.0.0.1:9000", addr)
	})
}

func TestBuildOutboundProxyRequest(t *testing.T) {
	requestBody := io.NopCloser(strings.NewReader("payload"))
	incomingReq := httptest.NewRequest(http.MethodPost, "http://example.com/original?trace=1", strings.NewReader("ignored"))
	incomingReq.Header.Set("Connection", "keep-alive")
	incomingReq.Header.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz")
	incomingReq.Header.Set("X-Test-Header", "ok")
	targetURL := &url.URL{Host: "example.com:8080", Path: "/rewritten", RawQuery: "trace=1"}

	proxyReq := buildOutboundProxyRequest(incomingReq, targetURL, requestBody)

	assert.Equal(t, "", proxyReq.RequestURI)
	assert.Equal(t, "example.com:8080", proxyReq.Host)
	assert.Equal(t, "/rewritten?trace=1", proxyReq.URL.RequestURI())
	assert.Equal(t, "ok", proxyReq.Header.Get("X-Test-Header"))
	assert.Empty(t, proxyReq.Header.Get("Connection"))
	assert.Empty(t, proxyReq.Header.Get("Proxy-Authorization"))
}

func TestServer_HandleHTTP_ReadResponseError(t *testing.T) {
	logger := zerolog.New(io.Discard)

	server := New(&Config{
		Logger:            &logger,
		ClientConnTimeout: 2 * time.Second,
		Resolver: resolverFunc(func(host string) (net.IP, error) {
			assert.Equal(t, "example.com", host)
			return net.ParseIP("127.0.0.1"), nil
		}),
		Dial: func(network, addr string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			go func() {
				defer serverConn.Close()
				_, _ = io.Copy(io.Discard, serverConn)
			}()
			return clientConn, nil
		},
	})

	proxyReq := httptest.NewRequest(http.MethodGet, "http://example.com/health", nil)
	rr := httptest.NewRecorder()

	server.ServeHTTP(rr, proxyReq)

	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Contains(t, rr.Body.String(), "Bad gateway: failed to read response")
}

func TestServer_HandleHTTP_DialTargetError(t *testing.T) {
	logger := zerolog.New(io.Discard)

	server := New(&Config{
		Logger:            &logger,
		ClientConnTimeout: 2 * time.Second,
		Resolver: resolverFunc(func(host string) (net.IP, error) {
			assert.Equal(t, "example.com", host)
			return net.ParseIP("127.0.0.1"), nil
		}),
		Dial: func(network, addr string) (net.Conn, error) {
			assert.Equal(t, "tcp", network)
			assert.Equal(t, "127.0.0.1:80", addr)
			return nil, errors.New("dial failed")
		},
	})

	proxyReq := httptest.NewRequest(http.MethodGet, "http://example.com/health", nil)
	rr := httptest.NewRecorder()

	server.ServeHTTP(rr, proxyReq)

	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Contains(t, rr.Body.String(), "Bad gateway: failed to send request")
}

func TestServer_HandleHTTP_WriteRequestError(t *testing.T) {
	logger := zerolog.New(io.Discard)

	server := New(&Config{
		Logger:            &logger,
		ClientConnTimeout: 2 * time.Second,
		Resolver: resolverFunc(func(host string) (net.IP, error) {
			assert.Equal(t, "example.com", host)
			return net.ParseIP("127.0.0.1"), nil
		}),
		Dial: func(network, addr string) (net.Conn, error) {
			assert.Equal(t, "tcp", network)
			assert.Equal(t, "127.0.0.1:80", addr)
			return &writeFailConn{}, nil
		},
	})

	proxyReq := httptest.NewRequest(http.MethodGet, "http://example.com/health", nil)
	rr := httptest.NewRecorder()

	server.ServeHTTP(rr, proxyReq)

	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Contains(t, rr.Body.String(), "Bad gateway: failed to send request")
}
