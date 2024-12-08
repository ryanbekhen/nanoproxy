package tor

import (
	"fmt"
	"github.com/rs/zerolog"
	"time"
)

func WaitForTorBootstrap(logger *zerolog.Logger, requester Requester, timeout time.Duration) error {
	complete := make(chan bool)

	go func() {
		for {
			if requester.RequestNewTorIdentity(nil) == nil {
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

func SwitcherIdentity(logger *zerolog.Logger, requester Requester, switchInterval time.Duration, done <-chan bool) {
	if err := WaitForTorBootstrap(logger, requester, 5*time.Minute); err != nil {
		logger.Error().Msg(err.Error())
		return
	}

	for {
		select {
		case <-done:
			return
		default:
			if err := requester.RequestNewTorIdentity(logger); err != nil {
				logger.Error().Msg(err.Error())
			}
			time.Sleep(switchInterval)
		}
	}
}
