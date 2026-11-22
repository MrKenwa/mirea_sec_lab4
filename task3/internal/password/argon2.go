// Package password реализует хеширование паролей через Argon2id.
package password

import (
	"crypto/rand"
	"crypto/subtle"

	"golang.org/x/crypto/argon2"
)

const memory uint32 = 19 * 1024 // КиБ.
const passes uint32 = 2
const threads uint8 = 1
const keyLength uint32 = 32

type Argon2id struct{}

func (Argon2id) Hash(password string) ([]byte, []byte) {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)

	hash := argon2.IDKey([]byte(password), salt, passes, memory, threads, keyLength)

	return salt, hash
}

func (Argon2id) Verify(password string, salt, expected []byte) bool {
	if len(salt) != 16 || len(expected) != int(keyLength) {
		return false
	}

	actual := argon2.IDKey([]byte(password), salt, passes, memory, threads, keyLength)

	return subtle.ConstantTimeCompare(actual, expected) == 1
}
