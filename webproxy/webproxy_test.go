package webproxy

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func Test_Middleware_WebProxy(t *testing.T) {
	t.Parallel()

	lnProxy, err := net.Listen("tcp", "127.0.0.1:0")
	utils.AssertEqual(t, nil, err)
	appProxy := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})
	proxy := New(time.Second * 5)
	appProxy.All("*", proxy.Handler)

	lnTarget, err := net.Listen("tcp", "127.0.0.1:0")
	utils.AssertEqual(t, nil, err)
	appTarget := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})
	appTarget.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	proxyAddr := lnProxy.Addr().String()
	targetAddr := lnTarget.Addr().String()

	go func() {
		utils.AssertEqual(t, nil, appProxy.Listener(lnProxy))
	}()
	go func() {
		utils.AssertEqual(t, nil, appTarget.Listener(lnTarget))
	}()

	proxyURL, err := url.Parse("http://" + proxyAddr)
	utils.AssertEqual(t, nil, err)

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	client := &http.Client{
		Transport: transport,
	}

	resp, err := client.Get("http://" + targetAddr)
	utils.AssertEqual(t, nil, err)

	body, err := io.ReadAll(resp.Body)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, "Hello, World!", string(body))
}

func Test_Middleware_WebProxy_HTTPS(t *testing.T) {
	t.Parallel()

	lnProxy, err := net.Listen("tcp", "127.0.0.1:0")
	utils.AssertEqual(t, nil, err)
	appProxy := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})
	proxy := New(time.Second * 5)
	appProxy.All("*", proxy.Handler)

	tlsconf, _, err := getTLSConfigs()
	utils.AssertEqual(t, nil, err)

	lnTarget, err := tls.Listen("tcp", "127.0.0.1:0", tlsconf)
	utils.AssertEqual(t, nil, err)
	appTarget := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})
	appTarget.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	proxyAddr := lnProxy.Addr().String()
	targetAddr := lnTarget.Addr().String()

	go func() {
		utils.AssertEqual(t, nil, appProxy.Listener(lnProxy))
	}()

	go func() {
		utils.AssertEqual(t, nil, appTarget.Listener(lnTarget))
	}()

	proxyURL, err := url.Parse("http://" + proxyAddr)
	utils.AssertEqual(t, nil, err)

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
	}

	resp, err := client.Get("https://" + targetAddr)
	utils.AssertEqual(t, nil, err)

	body, err := io.ReadAll(resp.Body)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, "Hello, World!", string(body))
}

// getTLSConfigs returns a server and client TLS config
// this code is copied from https://github.com/gofiber/fiber/blob/master/internal/tlstest/tls.go
func getTLSConfigs() (serverTLSConf, clientTLSConf *tls.Config, err error) {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Organization:  []string{"Fiber"},
			Country:       []string{"NL"},
			Province:      []string{""},
			Locality:      []string{"Amsterdam"},
			StreetAddress: []string{"Huidenstraat"},
			PostalCode:    []string{"1011 AA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	// pem encode
	var caPEM bytes.Buffer
	_ = pem.Encode(&caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	var caPrivKeyPEM bytes.Buffer
	_ = pem.Encode(&caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	})

	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Organization:  []string{"Fiber"},
			Country:       []string{"NL"},
			Province:      []string{""},
			Locality:      []string{"Amsterdam"},
			StreetAddress: []string{"Huidenstraat"},
			PostalCode:    []string{"1011 AA"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	var certPEM bytes.Buffer
	_ = pem.Encode(&certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	var certPrivateKeyPEM bytes.Buffer
	_ = pem.Encode(&certPrivateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivateKey),
	})

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivateKeyPEM.Bytes())
	if err != nil {
		return nil, nil, err
	}

	serverTLSConf = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caPEM.Bytes())
	clientTLSConf = &tls.Config{
		RootCAs: certPool,
	}

	return serverTLSConf, clientTLSConf, nil
}
