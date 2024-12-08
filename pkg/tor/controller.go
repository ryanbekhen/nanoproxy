package tor

import (
	"bufio"
	"fmt"
	"github.com/rs/zerolog"
	"strings"
)

type Controller struct {
	dialer Dialer
}

func NewTorController(dialer Dialer) *Controller {
	return &Controller{dialer: dialer}
}

func (t *Controller) RequestNewTorIdentity(logger *zerolog.Logger) error {
	conn, err := t.dialer.DialControlPort("tcp", "127.0.0.1:9051")
	if err != nil {
		return fmt.Errorf("failed to connect to tor control port: %w", err)
	}
	defer conn.Close()

	_, _ = fmt.Fprintf(conn, "AUTHENTICATE \"\"\r\n")
	_, err = fmt.Fprintf(conn, "SIGNAL NEWNYM\r\n")
	if err != nil {
		return fmt.Errorf("failed to request new identity: %w", err)
	}
	signalResponse, _ := bufio.NewReader(conn).ReadString('\n')
	if !strings.HasPrefix(signalResponse, "250") {
		return fmt.Errorf("failed to switch tor identity: %v", signalResponse)
	}

	if logger != nil {
		logger.Info().Msg("Tor identity changed")
	}

	return nil
}
