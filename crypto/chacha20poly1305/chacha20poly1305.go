package chacha20poly1305

import (
	"errors"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ocfbnj/shadowsocks-go/crypto"
	"github.com/ocfbnj/shadowsocks-go/crypto/cipher"
)

// The informations used by AEAD_CHACHA20_POLY1305.
// See https://shadowsocks.org/en/wiki/AEAD-Ciphers.html
const (
	KeySize   = 32
	SaltSize  = 32
	NonceSize = 12
	TagSize   = 16

	MaximumPayloadSize = 0x3FFF
)

type chacha20Poly1305 struct {
	key   [KeySize]byte
	salt  [SaltSize]byte
	nonce [NonceSize]byte

	havaSalt bool
}

// New returns a ChaCha20-Poly1305 AEAD that uses the given 256-bit key.
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	ret := new(chacha20Poly1305)
	copy(ret.key[:], key)
	return ret, nil
}

// NewWithPassword returns a ChaCha20-Poly1305 AEAD that uses the given 256-bit password
// to derive corresponding 256-bit key.
func NewWithPassword(password []byte) (cipher.AEAD, error) {
	key := crypto.DeriveKey(password, KeySize)
	return New(key)
}

func (c *chacha20Poly1305) Encrypt(plaintext []byte) ([]byte, error) {
	subkey, err := crypto.HkdfSha1(c.key[:], c.salt[:], []byte("ss-subkey"))
	if err != nil {
		return nil, err
	}

	// Should not have any error.
	aead, _ := chacha20poly1305.New(subkey)

	ciphertext := aead.Seal(nil, c.nonce[:], plaintext, nil)
	crypto.Increment(c.nonce[:])

	return ciphertext, nil
}

func (c *chacha20Poly1305) Decrypt(ciphertext []byte) ([]byte, error) {
	subkey, err := crypto.HkdfSha1(c.key[:], c.salt[:], []byte("ss-subkey"))
	if err != nil {
		return nil, err
	}

	// Should not have any error.
	aead, _ := chacha20poly1305.New(subkey)

	plaintext, err := aead.Open(nil, c.nonce[:], ciphertext, nil)
	if err != nil {
		return nil, err
	}
	crypto.Increment(c.nonce[:])

	return plaintext, nil
}

func (c *chacha20Poly1305) KeySize() int {
	return KeySize
}

func (c *chacha20Poly1305) SaltSize() int {
	return SaltSize
}

func (c *chacha20Poly1305) NonceSize() int {
	return NonceSize
}

func (c *chacha20Poly1305) TagSize() int {
	return TagSize
}

func (c *chacha20Poly1305) MaximumPayloadSize() int {
	return MaximumPayloadSize
}

func (c *chacha20Poly1305) Salt() []byte {
	if c.havaSalt {
		return c.salt[:]
	}

	return nil
}

func (c *chacha20Poly1305) SetSalt(salt []byte) {
	copy(c.salt[:], salt)
	c.havaSalt = true
}
