package socks5

import "errors"

var (
	ErrFailedToSendReply    = errors.New("failed to send reply")
	ErrUnrecognizedAddrType = errors.New("unrecognized address type")
)
