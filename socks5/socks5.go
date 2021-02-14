package socks5

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// VER is the value of VER field described in RFC 1928.
const VER = 0x05

// The methods defined in RFC 1928 section 3.
const (
	MethodNoAuthentication = 0x00
	MethodGSSAPI           = 0x01
	MethodUsernamePassword = 0x02
	MethodNoAcceptable     = 0xff
)

// The commands defined in RFC 1928 section 4.
const (
	CmdConnect = 0x01
	CmdBind    = 0x02
	CmdUDP     = 0x03
)

// The address types defined in RFC 1928 section 5.
const (
	AtypIPv4       = 0x01
	AtypDOMAINNAME = 0x03
	AtypIPv6       = 0x04
)

// The error types defined in RFC 1928 section 6.
const (
	ErrServerFailure      = Err(0x01)
	ErrNotAllowed         = Err(0x02)
	ErrNetworkUnreachable = Err(0x03)
	ErrHostUnreachable    = Err(0x04)
	ErrConnectionRefused  = Err(0x05)
)

// The maximum length of data.
const (
	maxMsgLen  = 3 + 1 + 1 + 255 + 2
	maxAddrLen = 1 + 1 + 255 + 2
)

var (
	errVersion = errors.New("SOCKS version error")
	errMethod  = errors.New("No supported method")
	errCommand = errors.New("No supported command")
	errAtyp    = errors.New("No supported address type")
)

// ReadTargetAddress returns a socks5 address.
func ReadTargetAddress(rw io.ReadWriter) (Addr, error) {
	buf := make([]byte, maxAddrLen)
	if _, err := io.ReadFull(rw, buf[:1]); err != nil {
		return nil, err
	}

	atyp := buf[0]

	switch atyp {
	case AtypIPv4:
		if _, err := io.ReadFull(rw, buf[1:1+net.IPv4len+2]); err != nil {
			return nil, err
		}
		return buf[:1+net.IPv4len+2], nil
	case AtypDOMAINNAME:
		if _, err := io.ReadFull(rw, buf[1:1+1]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(rw, buf[1+1:1+1+buf[1]+2]); err != nil {
			return nil, err
		}
		return buf[:1+1+buf[1]+2], nil
	case AtypIPv6:
		if _, err := io.ReadFull(rw, buf[1:1+net.IPv6len+2]); err != nil {
			return nil, err
		}
		return buf[:1+net.IPv6len+2], nil
	}

	return nil, errAtyp
}

// Handshake returns a target address.
func Handshake(rw io.ReadWriter) (Addr, error) {
	buf := make([]byte, maxMsgLen)

	// read the version and the number of methods
	if _, err := io.ReadFull(rw, buf[:2]); err != nil {
		return nil, err
	}

	// check version
	if buf[0] != VER {
		return nil, errVersion
	}

	// read methods
	if _, err := io.ReadFull(rw, buf[2:2+buf[1]]); err != nil {
		return nil, err
	}

	var i int
	for i = 0; i < int(buf[1]); i++ {
		if buf[2+i] == MethodNoAuthentication {
			break
		}
	}

	if i == int(buf[1]) {
		rw.Write([]byte{0x05, MethodNoAcceptable})
		return nil, errMethod
	}

	// sends a METHOD selection message
	if _, err := rw.Write([]byte{0x05, MethodNoAuthentication}); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(rw, buf[:3]); err != nil {
		return nil, err
	}

	if buf[0] != 0x05 {
		return nil, errVersion
	}

	if buf[1] != CmdConnect {
		rw.Write([]byte{0x05, 0x07, 0x00, AtypIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return nil, errCommand
	}

	// ok
	_, err := rw.Write([]byte{0x05, 0x00, 0x00, AtypIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return nil, err
	}

	return ReadTargetAddress(rw)
}

// Addr represents a address defined in RFC 1928 section 5.
type Addr []byte

func (addr Addr) String() string {
	atyp := addr[0]

	var host, port string

	switch atyp {
	case AtypIPv4:
		host = net.IP(addr[1 : 1+net.IPv4len]).String()
		port = strconv.Itoa(int(addr[1+net.IPv4len])<<8 | int(addr[1+net.IPv4len+1]))
	case AtypDOMAINNAME:
		host = string(addr[2 : 2+addr[1]])
		port = strconv.Itoa(int(addr[2+addr[1]])<<8 | int(addr[2+addr[1]+1]))
	case AtypIPv6:
		host = net.IP(addr[1 : 1+net.IPv6len]).String()
		port = strconv.Itoa(int(addr[1+net.IPv6len])<<8 | int(addr[1+net.IPv6len+1]))
	}

	return net.JoinHostPort(host, port)
}

// Err represents the error value of reply field defined in RFC 1928 section 6.
type Err byte

func (err Err) Error() string {
	return fmt.Sprintf("SOCKS5 error: %d", err)
}
