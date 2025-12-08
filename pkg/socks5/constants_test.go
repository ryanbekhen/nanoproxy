package socks5

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Command_String(t *testing.T) {
	var c Command
	c = CommandConnect
	assert.Equal(t, "connect", c.String())
	c = CommandBind
	assert.Equal(t, "bind", c.String())
	c = CommandAssociate
	assert.Equal(t, "associate", c.String())
	c = Command(0x04)
	assert.Equal(t, "unknown", c.String())
}

func Test_Command_Uint8(t *testing.T) {
	var c Command
	c = CommandConnect
	assert.Equal(t, uint8(0x01), c.Uint8())
	c = CommandBind
	assert.Equal(t, uint8(0x02), c.Uint8())
	c = CommandAssociate
	assert.Equal(t, uint8(0x03), c.Uint8())
	c = Command(0x04)
	assert.Equal(t, uint8(0x04), c.Uint8())
}

func Test_AddrType_Uint8(t *testing.T) {
	var a AddrType
	a = AddressTypeIPv4
	assert.Equal(t, uint8(0x01), a.Uint8())
	a = AddressTypeIPv6
	assert.Equal(t, uint8(0x04), a.Uint8())
	a = AddressTypeDomain
	assert.Equal(t, uint8(0x03), a.Uint8())
	a = AddrType(0x05)
	assert.Equal(t, uint8(0x05), a.Uint8())
}

func Test_Status_Uint8(t *testing.T) {
	var s Status
	s = StatusRequestGranted
	assert.Equal(t, uint8(0x00), s.Uint8())
	s = StatusGeneralFailure
	assert.Equal(t, uint8(0x01), s.Uint8())
	s = StatusConnectionNotAllowed
	assert.Equal(t, uint8(0x02), s.Uint8())
	s = StatusNetworkUnreachable
	assert.Equal(t, uint8(0x03), s.Uint8())
	s = StatusHostUnreachable
	assert.Equal(t, uint8(0x04), s.Uint8())
	s = StatusConnectionRefused
	assert.Equal(t, uint8(0x05), s.Uint8())
	s = StatusTTLExpired
	assert.Equal(t, uint8(0x06), s.Uint8())
	s = StatusCommandNotSupported
	assert.Equal(t, uint8(0x07), s.Uint8())
	s = StatusAddressNotSupported
	assert.Equal(t, uint8(0x08), s.Uint8())
	s = Status(0x09)
	assert.Equal(t, uint8(0x09), s.Uint8())
}
