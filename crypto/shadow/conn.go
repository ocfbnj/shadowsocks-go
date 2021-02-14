package shadow

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"

	"github.com/ocfbnj/shadowsocks-go/crypto/chacha20poly1305"
	"github.com/ocfbnj/shadowsocks-go/crypto/cipher"
)

// EncryptedConn encrypts a net.Conn.
type EncryptedConn interface {
	net.Conn
}

type encryptedConn struct {
	net.Conn

	deC cipher.AEAD
	enC cipher.AEAD

	buf       []byte
	index     int
	remaining int
}

// NewEncryptedConn returns a EncryptedConn providing confidentiality for conn.
func NewEncryptedConn(conn net.Conn, password []byte) EncryptedConn {
	// Should not go wrong.
	enC, _ := chacha20poly1305.NewWithPassword(password)
	deC, _ := chacha20poly1305.NewWithPassword(password)

	return &encryptedConn{Conn: conn, enC: enC, deC: deC}
}

func (ec *encryptedConn) Read(b []byte) (int, error) {
	if err := readSalt(ec.Conn, ec.deC); err != nil {
		return 0, err
	}

	if ec.remaining > 0 {
		n := copy(b, ec.buf[ec.index:ec.index+ec.remaining])
		ec.index += n
		ec.remaining -= n

		return n, nil
	}

	var err error
	ec.buf, err = readEncryptedPayload(ec.Conn, ec.deC)
	if err != nil {
		return 0, err
	}

	n := copy(b, ec.buf)
	ec.index = n
	ec.remaining = len(ec.buf) - n

	return n, nil
}

func (ec *encryptedConn) Write(b []byte) (int, error) {
	if err := writeSalt(ec.Conn, ec.enC); err != nil {
		return 0, err
	}

	return writeUnencryptedPayload(ec.Conn, ec.enC, b)
}

func readSalt(r io.Reader, deC cipher.AEAD) error {
	if deC.Salt() == nil {
		salt := make([]byte, deC.SaltSize())
		if _, err := io.ReadFull(r, salt); err != nil {
			return err
		}

		deC.SetSalt(salt)
	}

	return nil
}

func readEncryptedPayload(r io.Reader, deC cipher.AEAD) ([]byte, error) {
	tagSize := deC.TagSize()
	buf := make([]byte, deC.MaximumPayloadSize()+tagSize)

	// read encrypted length
	n, err := io.ReadFull(r, buf[:2+tagSize])
	if err != nil {
		return nil, err
	}

	lenBuf, err := deC.Decrypt(buf[:n])
	if err != nil {
		return nil, err
	}

	payloadLen := (int(lenBuf[0])<<8 | int(lenBuf[1])) & deC.MaximumPayloadSize()

	// read encrypted payload
	n, err = io.ReadFull(r, buf[:payloadLen+tagSize])
	if err != nil {
		return nil, err
	}

	plaintext, err := deC.Decrypt(buf[:n])
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func writeSalt(w io.Writer, enC cipher.AEAD) error {
	if enC.Salt() == nil {
		salt := make([]byte, enC.SaltSize())
		if _, err := rand.Read(salt); err != nil {
			return err
		}

		if _, err := w.Write(salt); err != nil {
			return err
		}

		enC.SetSalt(salt)
	}

	return nil
}

func writeUnencryptedPayload(w io.Writer, enC cipher.AEAD, b []byte) (int, error) {
	remaining := len(b)
	nWrite := 0
	maximumPayloadSize := enC.MaximumPayloadSize()

	for remaining > 0 {
		payloadLen := uint16(remaining)
		if remaining > maximumPayloadSize {
			payloadLen = uint16(maximumPayloadSize)
		}

		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, payloadLen)

		// write encrypted length of payload
		ciphertext, err := enC.Encrypt(lenBuf)
		if err != nil {
			return nWrite, err
		}

		if _, err := w.Write(ciphertext); err != nil {
			return nWrite, err
		}

		// write encrypted payload
		ciphertext, err = enC.Encrypt(b[nWrite : nWrite+int(payloadLen)])
		if err != nil {
			return nWrite, err
		}

		if _, err := w.Write(ciphertext); err != nil {
			return nWrite, err
		}

		nWrite += int(payloadLen)
		remaining -= int(payloadLen)
	}

	return nWrite, nil
}
