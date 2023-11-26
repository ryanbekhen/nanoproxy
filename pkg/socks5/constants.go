package socks5

type Command uint8

func (c Command) Uint8() uint8 {
	return uint8(c)
}

func (c Command) String() string {
	switch c {
	case CommandConnect:
		return "connect"
	case CommandBind:
		return "bind"
	case CommandAssociate:
		return "associate"
	default:
		return "unknown"
	}
}

type AddrType uint8

func (a AddrType) Uint8() uint8 {
	return uint8(a)
}

type Status uint8

func (s Status) Uint8() uint8 {
	return uint8(s)
}

const (
	Version uint8 = 0x05

	CommandConnect   Command = 0x01
	CommandBind      Command = 0x02
	CommandAssociate Command = 0x03

	StatusRequestGranted       Status = 0x00
	StatusGeneralFailure       Status = 0x01
	StatusConnectionNotAllowed Status = 0x02
	StatusNetworkUnreachable   Status = 0x03
	StatusHostUnreachable      Status = 0x04
	StatusConnectionRefused    Status = 0x05
	StatusTTLExpired           Status = 0x06
	StatusCommandNotSupported  Status = 0x07
	StatusAddressNotSupported  Status = 0x08

	AddressTypeIPv4   AddrType = 0x01
	AddressTypeIPv6   AddrType = 0x04
	AddressTypeDomain AddrType = 0x03
)
