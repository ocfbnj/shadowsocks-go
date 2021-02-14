package cipher

// AEAD provides encryption and decryption for shadowsocks.
// See https://shadowsocks.org/en/wiki/AEAD-Ciphers.html
type AEAD interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)

	KeySize() int
	SaltSize() int
	NonceSize() int
	TagSize() int

	MaximumPayloadSize() int

	Salt() []byte
	SetSalt(salt []byte)
}
