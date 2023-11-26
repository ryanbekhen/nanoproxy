package socks5

import "errors"

var (
	ErrInvalidHeader              = errors.New("invalid header")
	ErrUnsupportedVersion         = errors.New("unsupported SOCKS version")
	ErrInvalidAddressType         = errors.New("invalid address type")
	ErrUnrecognizedAddrType       = errors.New("unrecognized address type")
	ErrFailedToResolveDestination = errors.New("failed to resolve destination")
	ErrFailedToSendReply          = errors.New("failed to send reply")
	ErrUnsupportedCommand         = errors.New("unsupported command")
	ErrFailedToConnect            = errors.New("failed to connect")
	ErrUnsupportedAuthVersion     = errors.New("unsupported authentication version")
	ErrFailedToGetAuthMethods     = errors.New("failed to get authentication methods")
)
