package cryptography

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_HashPassword(t *testing.T) {
	salt, err := RandomHex(32)
	hash, err := HashPassword("some-password", salt)
	if err != nil {
		t.Fatal(err.Error())
	}
	assert.Equal(t, 64, len(hash))

	hash, err = HashPassword("1234567", salt)
	if err == nil {
		t.Fatal("should have raised an error on too short password")
	}
	assert.Equal(t, err.Error(), "HashPassword: proposed password with length [7] is too short")
}

func Test_HashPasswordCustom(t *testing.T) {
	salt, err := RandomHex(32)
	hash, err := HashPasswordCustom("some-password", salt, 1, 1*64*1024, 2, 32)
	if err != nil {
		t.Fatal(err.Error())
	}
	assert.Equal(t, 64, len(hash))

	hash, err = HashPasswordCustom("1234567", salt, 1, 1*64*1024, 2, 32)
	if err == nil {
		t.Fatal("should have raised an error on too short password")
	}
	assert.Equal(t, err.Error(), "HashPassword: proposed password with length [7] is too short")
}
