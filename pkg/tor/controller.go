package tor

import (
	"bufio"
	"fmt"
	"github.com/rs/zerolog"
)

type Controller struct {
	dialer Dialer
}

func NewTorController(dialer Dialer) *Controller {
	return &Controller{dialer: dialer}
}

func (t *Controller) RequestNewTorIdentity(logger *zerolog.Logger) error {
	conn, err := t.dialer.Dial("tcp", "127.0.0.1:9051")
	if err != nil {
		return fmt.Errorf("failed to connect to tor control port: %w", err)
	}
	defer conn.Close()

	_, _ = fmt.Fprintf(conn, "AUTHENTICATE\r\n")
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

	if logger != nil {
		logger.Info().Msg("Tor identity changed")
	}

	return nil
}
