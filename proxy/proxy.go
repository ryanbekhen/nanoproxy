package proxy

import (
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type Proxy struct {
	TunnelTimeout time.Duration // tunnel timeout in seconds (default 15s)
}

func New(tunnelTimeout time.Duration) *Proxy {
	return &Proxy{tunnelTimeout}
}

// ServeHTTP handles incoming HTTP requests and proxies them to the destination server
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s", net.JoinHostPort(extractClientAddressFromRequest(r)), r.Method, r.URL)
	if r.Method == http.MethodConnect {
		p.handleTunneling(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleTunneling handles CONNECT requests by establishing two-way connections to both the client and server
func (p *Proxy) handleTunneling(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, p.TunnelTimeout)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// HTTP/1.1 200 OK\r\n\r\n
	w.WriteHeader(http.StatusOK)

	// hijack the connection from the HTTP server
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	// get the underlying TCP connection from the Hijacker
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// close the underlying TCP connection when we return from this function or if anything else goes wrong
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

// handleHTTP handles HTTP proxy requests by copying the request and response bodies to the destination server
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// create a new HTTP request by copying the incoming request (r) and
	// changing the URL scheme and host to the destination server
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	// copy all headers from the response to the client
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// transfer bytes from src to dst until either EOF is reached on src or an error occurs
func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer func() {
		_ = destination.Close()
		_ = source.Close()
	}()
	_, _ = io.Copy(destination, source)
}

// copyHeader copies headers from src to dst and adds them to dst if they are not already present in dst
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// extractClientAddressFromRequest extracts the client IP address from the request headers
func extractClientAddressFromRequest(r *http.Request) (string, string) {
	var clientAddr string
	if ips := r.Header.Get("x-forwarded-for"); len(ips) > 0 {
		clientAddr = strings.Split(ips, ",")[0]
	} else if ips := r.Header.Get("cf-connecting-ip"); len(ips) > 0 {
		clientAddr = strings.Split(ips, ",")[0]
	} else if ips := r.Header.Get("x-real-ip"); len(ips) > 0 {
		clientAddr = strings.Split(ips, ",")[0]
	} else {
		clientAddr = r.RemoteAddr
	}

	return extractClientAddress(clientAddr, r)
}

// extractClientAddress extracts the client IP address from the request headers
func extractClientAddress(clientAddr string, source interface{}) (string, string) {
	var clientIP, clientPort string

	if clientAddr != "" {
		clientAddr = strings.TrimSpace(clientAddr)
		if host, port, err := net.SplitHostPort(clientAddr); err == nil {
			clientIP = host
			clientPort = port
		} else {
			var addrErr *net.AddrError
			if errors.As(err, &addrErr) {
				switch addrErr.Err {
				case "missing port in address":
					fallthrough
				case "too many colons in address":
					clientIP = clientAddr
				default:
				}
			}
		}
	}

	if clientIP == "" {
		if r, isRequest := source.(*http.Request); isRequest {
			source = map[string]interface{}{"headers": r.Header, "remote_addr": r.RemoteAddr}
		}
	}

	return clientIP, clientPort
}
