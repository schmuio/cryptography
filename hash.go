package cryptography

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// HashPassword creates a password hash using the Argon2id algorithm (https://www.password-hashing.net/argon2-specs.pdf),
// generating an output resistant to dictionary and brute-force attacks specific to MD5 and SHA-X hashing algorithms,
// please check [https://cryptobook.nakov.com/mac-and-key-derivation/password-encryption] for details.
//
// Parameters are selected using 11th Gen Intel® Core™ i9-11900H @ 2.50GHz × 16 / 32 RAM - performance will vary depending
// on the host system executing the function.
//
// (!) IMPORTANT: Never use vanilla SHA-X or MD5 hashing algorithms for saving passwords because if the risks related to
// those algorithms, namely using rainbow tables or brute-forcing based on GPUs, FPGAs or ASICs that allow efficient computation
// of a sheer amount of hashes at high speed.
func HashPassword(password string, salt string) (string, error) {
	if len(password) < 8 {
		return "", fmt.Errorf("HashPassword: proposed password with length [%v] is too short", len(password))
	}
	hash := argon2.IDKey([]byte(password), []byte(salt), 2, 1*256*1024, 4, 32)
	return hex.EncodeToString(hash), nil
}

// HashPasswordCustom allows arbitrary tuning of the parameters of the underlying argon2 algorithm
func HashPasswordCustom(password string, salt string, time, memory uint32, threads uint8, keyLen uint32) (string, error) {
	if len(password) < 8 {
		return "", fmt.Errorf("HashPassword: proposed password with length [%v] is too short", len(password))
	}
	hash := argon2.IDKey([]byte(password), []byte(salt), time, memory, threads, keyLen)
	return hex.EncodeToString(hash), nil
}
