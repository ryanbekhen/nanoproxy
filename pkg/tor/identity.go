package tor

import (
	"bufio"
	"fmt"
	"github.com/rs/zerolog"
	"net"
	"time"
)

func waitForTorBootstrap(logger *zerolog.Logger, timeout time.Duration) error {
	complete := make(chan bool)

	go func() {
		for {
			if requestNewTorIdentity(nil) == nil {
				complete <- true
				break
			}
			time.Sleep(5 * time.Second)
		}
	}()

	select {
	case <-complete:
		logger.Info().Msg("Tor bootstrap done")
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timeout: Tor bootstrap not complete after %s", timeout)
	}
}

func SwitcherIdentity(logger *zerolog.Logger, switchInterval time.Duration) {
	if err := waitForTorBootstrap(logger, 5*time.Minute); err != nil {
		logger.Error().Msg(err.Error())
		return
	}

	for {
		if err := requestNewTorIdentity(logger); err != nil {
			logger.Error().Msg(err.Error())
		}
		time.Sleep(switchInterval)
	}
}

func requestNewTorIdentity(logger *zerolog.Logger) error {
	conn, err := net.Dial("tcp", "127.0.0.1:9051")
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
