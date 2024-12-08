package tor_test

import (
	"bytes"
	"fmt"
	"github.com/ryanbekhen/nanoproxy/pkg/tor"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

type MockRequester struct {
	shouldFail bool
	callCount  int
}

func (m *MockRequester) RequestNewTorIdentity(logger *zerolog.Logger) error {
	m.callCount++
	if m.shouldFail {
		return fmt.Errorf("simulated failure")
	}
	return nil
}

func TestSwitcherIdentity(t *testing.T) {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: &bytes.Buffer{}}).With().Logger()
	requester := &MockRequester{shouldFail: false}
	done := make(chan bool)

	// Set up a Goroutine to stop the SwitcherIdentity after a short delay
	go func() {
		time.Sleep(10 * time.Millisecond)
		done <- true
	}()

	// Call the SwitcherIdentity function with a very short interval
	go tor.SwitcherIdentity(&logger, requester, 1*time.Millisecond, done)

	// Wait for a moment to ensure goroutine have run
	time.Sleep(15 * time.Millisecond)

	assert.True(t, requester.callCount > 0, "expected SwitcherIdentity to call RequestNewTorIdentity multiple times")
}
