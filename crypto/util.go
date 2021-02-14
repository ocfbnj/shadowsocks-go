package crypto

import (
	"crypto/md5"
	"crypto/sha1"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Increment increase the num by 1.
func Increment(num []byte) {
	l := len(num)
	for i := 0; i < l; i++ {
		num[i]++
		if num[i] != 0 {
			break
		}
	}
}

// DeriveKey generate a key from a password.
func DeriveKey(password []byte, keySize int) []byte {
	h := md5.New()
	var buf []byte

	for len(buf) < keySize {
		h.Write(buf)
		h.Write(password)
		buf = h.Sum(buf)
		h.Reset()
	}

	return buf[:keySize]
}

// HkdfSha1 takes a secret key, a non-secret salt, an info string,
// and produces a subkey that is cryptographically strong even if the input secret key is weak.
//
// The info string must be the string "ss-subkey" without quotes.
func HkdfSha1(key, salt, info []byte) ([]byte, error) {
	subkey := make([]byte, len(key))
	r := hkdf.New(sha1.New, key, salt, info)

	if _, err := io.ReadFull(r, subkey); err != nil {
		return nil, err
	}

	return subkey, nil
}
