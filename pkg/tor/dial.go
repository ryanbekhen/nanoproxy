package tor

import (
	"bufio"
	"fmt"
	"github.com/rs/zerolog"
	"golang.org/x/net/proxy"
	"net"
	"os"
	"time"
)

func Dial(network, addr string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", "localhost:9050", nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create tor dialer: %w", err)
	}

	return dialer.Dial(network, addr)
}

func readAuthenticationCookie() (string, error) {
	file, err := os.Open("/opt/homebrew/var/lib/tor/control_auth_cookie")
	if err != nil {
		return "", fmt.Errorf("failed to open tor control auth cookie: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan()

	return scanner.Text(), nil
}

func SwitcherIdentity(logger *zerolog.Logger, switchInterval time.Duration) {
	for {
		if err := requestNewTorIdentity(logger); err != nil {
			logger.Error().Msg(err.Error())
		}
		time.Sleep(switchInterval)
	}
}

func requestNewTorIdentity(logger *zerolog.Logger) error {
	conn, err := net.Dial("tcp", "localhost:9051")
	if err != nil {
		return fmt.Errorf("failed to connect to tor control port: %w", err)
	}
	defer conn.Close()

	cookie, err := readAuthenticationCookie()
	if err != nil {
		return fmt.Errorf("failed to read tor control auth cookie: %w", err)
	}
	_, _ = fmt.Fprintf(conn, "AUTHENTICATE \"%s\"\r\n", cookie)
	_, _ = fmt.Fprintf(conn, "SIGNAL NEWNYM\r\n")

	authStatus, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || authStatus != "250 OK\r\n" {
		return fmt.Errorf("failed to authenticate with tor control port: %w", err)
	}

	_, _ = fmt.Fprintf(conn, "SIGNAL NEWNYM\r\n")
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || status != "250 OK\r\n" {
		return fmt.Errorf("failed to switch tor identity: %w", err)
	}

	logger.Info().Msg("Tor identity changed")

	return nil
}
