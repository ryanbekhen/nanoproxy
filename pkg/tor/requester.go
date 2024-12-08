package tor

import "github.com/rs/zerolog"

type Requester interface {
	RequestNewTorIdentity(logger *zerolog.Logger) error
}
