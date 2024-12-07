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
			if checkTorBootstrapStatus() {
				complete <- true
				return
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

func checkTorBootstrapStatus() bool {
	conn, err := net.Dial("tcp", "127.0.0.1:9051")
	if err != nil {
		fmt.Println("Error connecting to Tor control port:", err)
		return false
	}
	defer conn.Close()

	_, err = conn.Write([]byte("GETINFO status/bootstrap-phase\r\n"))
	if err != nil {
		fmt.Println("Error sending command:", err)
		return false
	}

	buffer := make([]byte, 2048)
	_, err = conn.Read(buffer)
	if err != nil {
		fmt.Println("Error reading from Tor control port:", err)
		return false
	}

	if string(buffer) == "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100\r\n" {
		return true
	}

	return false
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

	logger.Info().Msg("Tor identity changed")

	return nil
}
