package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"github.com/stretchr/testify/assert"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestProxy_ServeHTTP(t *testing.T) {
	t.Run("HTTP", func(t *testing.T) {
		expectedResponse := "Expected Response"
		destServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(expectedResponse))
		}))
		defer destServer.Close()
		destServerURL, _ := url.Parse(destServer.URL)

		proxyServer := httptest.NewServer(New(0))
		proxyServerURL, _ := url.Parse(proxyServer.URL)
		defer proxyServer.Close()

		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyServerURL)}}
		res, err := client.Get(destServerURL.String())
		assert.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		defer res.Body.Close()
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, expectedResponse, string(body))
	})

	t.Run("HTTPS", func(t *testing.T) {
		expectedResponse := "Expected Response"
		destServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(expectedResponse))
		}))
		defer destServer.Close()
		destServerURL, _ := url.Parse(destServer.URL)

		proxyServer := httptest.NewServer(New(0))
		proxyServerURL, _ := url.Parse(proxyServer.URL)
		defer proxyServer.Close()

		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyServerURL),
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
		res, err := client.Get(destServerURL.String())
		assert.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		defer res.Body.Close()
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, expectedResponse, string(body))
	})
}

func TestProxy_HandleHTTP_InvalidDestinationServer(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &Proxy{}
		p.handleHTTP(w, r)
	}))
	defer proxyServer.Close()
	proxyServerURL, _ := url.Parse(proxyServer.URL)

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyServerURL)}}
	res, err := client.Get("http://localhost:3000")
	assert.NoError(t, err)

	_, err = io.ReadAll(res.Body)
	defer res.Body.Close()

	assert.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
}

func TestProxy_HandleTunneling_InvalidDestinationServer(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &Proxy{}
		p.handleTunneling(w, r)
	}))
	defer proxyServer.Close()
	proxyServerURL, _ := url.Parse(proxyServer.URL)

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyServerURL)}}
	_, err := client.Get("https://localhost:3000")
	assert.Error(t, err)
}

type mockNoHijackerResponseWriter struct {
	http.ResponseWriter
}

func TestProxy_HandleTunneling_HijackNotSupported(t *testing.T) {
	expectedResponse := "Expected Response"
	destServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(expectedResponse))
	}))
	defer destServer.Close()
	destServerURL, _ := url.Parse(destServer.URL)

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &Proxy{}
		p.handleTunneling(&mockNoHijackerResponseWriter{w}, r)
	}))
	defer proxyServer.Close()
	proxyServerURL, _ := url.Parse(proxyServer.URL)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyServerURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	_, err := client.Get(destServerURL.String())
	assert.Error(t, err)
}

type mockHijacker struct {
	http.ResponseWriter
}

func (m *mockHijacker) WriteHeader(int) {}

func (m *mockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("hijack error")
}

func TestProxy_HandleTunneling_HijackError(t *testing.T) {
	expectedResponse := "Expected Response"
	destServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(expectedResponse))
	}))
	defer destServer.Close()
	destServerURL, _ := url.Parse(destServer.URL)

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &Proxy{}
		p.handleTunneling(&mockHijacker{w}, r)
	}))
	defer proxyServer.Close()
	proxyServerURL, _ := url.Parse(proxyServer.URL)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyServerURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	_, err := client.Get(destServerURL.String())
	assert.Error(t, err)
}

func TestExtractClientAddressFromRequest(t *testing.T) {
	tests := []struct {
		name         string
		headers      map[string]string
		remoteAddr   string
		expectedIP   string
		expectedPort string
	}{
		{
			name:         "x-forwarded-for header",
			headers:      map[string]string{"x-forwarded-for": "192.168.1.1, 192.168.1.2", "x-real-ip": "192.168.1.3"},
			remoteAddr:   "127.0.0.1:12345",
			expectedIP:   "192.168.1.1",
			expectedPort: "",
		},
		{
			name:         "cf-connecting-ip header",
			headers:      map[string]string{"cf-connecting-ip": "192.168.2.1"},
			remoteAddr:   "127.0.0.1:12345",
			expectedIP:   "192.168.2.1",
			expectedPort: "",
		},
		{
			name:         "x-real-ip header",
			headers:      map[string]string{"x-real-ip": "192.168.3.1"},
			remoteAddr:   "127.0.0.1:12345",
			expectedIP:   "192.168.3.1",
			expectedPort: "",
		},
		{
			name:         "fallback to remoteAddr",
			headers:      map[string]string{},
			remoteAddr:   "192.168.4.1:54321",
			expectedIP:   "192.168.4.1",
			expectedPort: "54321",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			actualIP, actualPort := extractClientAddressFromRequest(req)
			assert.Equal(t, tt.expectedIP, actualIP)
			assert.Equal(t, tt.expectedPort, actualPort)
		})
	}
}
