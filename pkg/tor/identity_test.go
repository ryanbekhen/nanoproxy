package tor

import (
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// Mock Requester untuk menggantikan implementasi sebenarnya
type MockRequester struct {
	RequestNewTorIdentityFunc func(logger *zerolog.Logger) error
}

func (m *MockRequester) RequestNewTorIdentity(logger *zerolog.Logger) error {
	return m.RequestNewTorIdentityFunc(logger)
}

func TestWaitForTorBootstrap(t *testing.T) {
	logger := zerolog.Nop()
	timeout := 2 * time.Second

	t.Run("Successful bootstrap", func(t *testing.T) {
		mockRequester := &MockRequester{
			RequestNewTorIdentityFunc: func(logger *zerolog.Logger) error {
				return nil // selalu sukses
			},
		}

		err := WaitForTorBootstrap(&logger, mockRequester, timeout)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("Timeout occurs", func(t *testing.T) {
		mockRequester := &MockRequester{
			RequestNewTorIdentityFunc: func(logger *zerolog.Logger) error {
				time.Sleep(3 * time.Second) // memicu timeout
				return nil
			},
		}

		err := WaitForTorBootstrap(&logger, mockRequester, timeout)
		if err == nil {
			t.Errorf("expected timeout error, got nil")
		}
	})

	t.Run("Error in RequestNewTorIdentity", func(t *testing.T) {
		mockRequester := &MockRequester{
			RequestNewTorIdentityFunc: func(logger *zerolog.Logger) error {
				return errors.New("requester error")
			},
		}

		err := WaitForTorBootstrap(&logger, mockRequester, timeout)
		if err == nil || err.Error() != "timeout: Tor bootstrap not complete after 2s" {
			t.Errorf("expected timeout error due to RequestNewTorIdentity failure, got %v", err)
		}
	})
}

func TestSwitcherIdentity(t *testing.T) {
	logger := zerolog.Nop()
	switchInterval := 1 * time.Second
	done := make(chan bool, 1)

	t.Run("Switcher stops when done signal is received", func(t *testing.T) {
		mockRequester := &MockRequester{
			RequestNewTorIdentityFunc: func(logger *zerolog.Logger) error {
				return nil
			},
		}

		go func() {
			time.Sleep(2 * time.Second)
			done <- true
		}()

		go func() {
			SwitcherIdentity(&logger, mockRequester, switchInterval, done)
		}()

		time.Sleep(3 * time.Second)
		// Tidak ada log error karena mockRequester selalu berhasil
	})
}
