package cryptography

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

// AEAD - AES GCM - native
//////////////////////////////////////////////////////////////////////////////////
func TestEncryptAesGcm_OnFaultyKey(t *testing.T) {
	// Want: consistent rejection in case of empty or incorrect-length keys
	for _, faultyKey := range []string{"", "odd", "3f07fb18", "ef65a7ac36a5d6c56cd6cd63e8683b9e5f3c8cbdf27650afc257285f75d4bf38209a899dee8348ddb8d49cf00a26f2118fd479b2ae10c8397b4cf52bce342bf3"} {
		ciphertext, err := EncryptAesGcm("some-plaintext", faultyKey)
		assert.Equal(t, "", ciphertext)
		assert.Contains(t, err.Error(), "EncryptAesGcm failed to create new block with error: [crypto/aes: invalid key size")
	}
}

func TestEncryptAesGcm_PositivePath(t *testing.T) {
	// Want: the function encrypts the plaintext correctly
	key, err := Key256b()
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	for _, plaintext := range []string{"", "some-text", "ef65a7ac36a5d6c56cd6cd63e8683b9e5f3c8cbdf27650afc257285f75d4bf38209a899dee8348ddb8d49cf00a26f2118fd479b2ae10c8397b4cf52bce342bf3"} {
		ciphertext, err := EncryptAesGcm(plaintext, key)
		if err != nil {
			t.Errorf(err.Error())
		}
		assert.Greater(t, len(ciphertext), 32)
		decryptedCiphertext, err := DecryptAesGcm(ciphertext, key)
		if err != nil {
			t.Errorf(err.Error())
		}
		assert.Equal(t, plaintext, decryptedCiphertext)
	}

	// Want: ciphertext is not deterministic
	plaintext2repeat := "will-be-encrypted-twice"
	ciphertext1, err := EncryptAesGcm(plaintext2repeat, key)
	if err != nil {
		t.Errorf(err.Error())
	}
	ciphertext2, err := EncryptAesGcm(plaintext2repeat, key)
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.NotEqual(t, ciphertext1, ciphertext2)
}

func TestDecryptAesGcm_OnFaultyKey(t *testing.T) {
	// Want: consistent rejection in case of empty or incorrect-length keys
	key, err := Key256b()
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	plaintext := "some-plaintext-to-encrypt"
	ciphertext, err := EncryptAesGcm(plaintext, key) // Ensure the ciphertext is legitimate
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}

	for _, faultyKey := range []string{"", "odd", "definitely-not-a-hex", "3f07fb18", "ef65a7ac36a5d6c56cd6cd63e8683b9e5f3c8cbdf27650afc257285f75d4bf38209a899dee8348ddb8d49cf00a26f2118fd479b2ae10c8397b4cf52bce342bf3"} {
		plaintext, err := DecryptAesGcm(ciphertext, faultyKey)
		assert.Equal(t, "", plaintext)
		assert.Contains(t, err.Error(), "DecryptAesGcm failed to create new block with error: [crypto/aes: invalid key size")
	}
}

func TestDecryptAesGcm_TooShortCiphertext(t *testing.T) {
	// Want: respond to random ciphertext with the expected error, no panic events (this is important because otherwise the function can be crashed with an out-of-bounds error)
	key, err := Key256b()
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	for _, faultyCiphertext := range []string{"", "3f07fb18"} {
		plaintext, err := DecryptAesGcm(faultyCiphertext, key)
		assert.Equal(t, "", plaintext)
		assert.Contains(t, err.Error(), "DecryptAesGcm failed to ciphertext - input too short")
	}
}

func TestDecryptAesGcm_NonHexCiphertext(t *testing.T) {
	// Want: respond to non-hex ciphertext with the expected error
	key, err := Key256b()
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	for _, faultyCiphertext := range []string{"x", "11abg"} {
		plaintext, err := DecryptAesGcm(faultyCiphertext, key)
		assert.Equal(t, "", plaintext)
		assert.Contains(t, err.Error(), "DecryptAesGcm failed to decode ciphertext hex to bytes")
		assert.Contains(t, err.Error(), "ensure ciphertext contains valid hex digits only")
	}
}

func TestDecryptAesGcm_InvalidCiphertext(t *testing.T) {
	// Want: respond with encryption/decryption error
	keyForEncrypt, err := Key256b()
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	differentKey, err := Key256b()
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	faultyCiphertext1 := "b4e30671a3ddca44201d4a6998f315f38010441d41eb72dad55070cd133e111d2520407b4791bab0092417dd7b3a58303606afe23ae331c31e6c9983db17e06c"
	faultyCiphertext2, err := EncryptAesGcm("some-plain-text", keyForEncrypt)

	for _, faultyCiphertext := range []string{faultyCiphertext1, faultyCiphertext2} {
		plaintext, err := DecryptAesGcm(faultyCiphertext, differentKey)
		assert.Equal(t, "", plaintext)
		assert.Contains(t, err.Error(), "failed to decrypt ciphertext with error: cipher: message authentication failed")
	}
}

func TestDecryptAesGcm_PositivePath(t *testing.T) {
	// Want: the entire encrypt-decrypt cycle works end-to-end
	originalPlaintext := "some-pretty-important-plaintext"
	key, err := Key256b()
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	ciphertext, err := EncryptAesGcm(originalPlaintext, key)
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	decryptedPlaintext, err := DecryptAesGcm(ciphertext, key)
	assert.Equal(t, originalPlaintext, decryptedPlaintext)
}

// AEAD - ChaCha20-Poly1305 - native
//////////////////////////////////////////////////////////////////////////////////
func Test_EncryptChaCha20_OnFaultyKey(t *testing.T) {
	// Want: consistent rejection in case of empty or incorrect-length keys
	for _, faultyKey := range []string{"", "odd", "3f07fb18", "ef65a7ac36a5d6c56cd6cd63e8683b9e5f3c8cbdf27650afc257285f75d4bf38209a899dee8348ddb8d49cf00a26f2118fd479b2ae10c8397b4cf52bce342bf3"} {
		ciphertext, err := EncryptChaCha20("some-plaintext", faultyKey)
		assert.Equal(t, "", ciphertext)
		assert.Contains(t, err.Error(), "EncryptChaCha20: failed to create eaed primitive with error: [chacha20poly1305: bad key length]")
	}
}

func Test_EncryptChaCha20_PositivePath(t *testing.T) {
	// Want: the function encrypts the plaintext correctly
	key, err := Key256b()
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	for _, plaintext := range []string{"", "some-text", "ef65a7ac36a5d6c56cd6cd63e8683b9e5f3c8cbdf27650afc257285f75d4bf38209a899dee8348ddb8d49cf00a26f2118fd479b2ae10c8397b4cf52bce342bf3"} {
		ciphertext, err := EncryptChaCha20(plaintext, key)
		if err != nil {
			t.Errorf(err.Error())
		}
		assert.Greater(t, len(ciphertext), 32)
		decryptedCiphertext, err := DecryptChaCha20(ciphertext, key)
		if err != nil {
			t.Errorf(err.Error())
		}
		assert.Equal(t, plaintext, decryptedCiphertext)
	}

	// Want: ciphertext is not deterministic
	plaintext2repeat := "will-be-encrypted-twice"
	ciphertext1, err := EncryptChaCha20(plaintext2repeat, key)
	if err != nil {
		t.Errorf(err.Error())
	}
	ciphertext2, err := EncryptChaCha20(plaintext2repeat, key)
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.NotEqual(t, ciphertext1, ciphertext2)
}

func Test_DecryptChaCha20_OnFaultyKey(t *testing.T) {
	// Want: consistent rejection in case of empty or incorrect-length keys
	key, err := Key256b()
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	plaintext := "some-plaintext-to-encrypt"
	ciphertext, err := EncryptChaCha20(plaintext, key) // Ensure the ciphertext is legitimate
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}

	for _, faultyKey := range []string{"", "odd", "definitely-not-a-hex", "3f07fb18", "ef65a7ac36a5d6c56cd6cd63e8683b9e5f3c8cbdf27650afc257285f75d4bf38209a899dee8348ddb8d49cf00a26f2118fd479b2ae10c8397b4cf52bce342bf3"} {
		plaintext, err := DecryptChaCha20(ciphertext, faultyKey)
		assert.Equal(t, "", plaintext)
		assert.Contains(t, err.Error(), "DecryptChaCha20: failed to create eaed primitive with error: [chacha20poly1305: bad key length]")
	}
}

func Test_DecryptChaCha20_TooShortCiphertext(t *testing.T) {
	// Want: respond to random ciphertext with the expected error, no panic events (this is important because otherwise the function can be crashed with an out-of-bounds error)
	key, err := Key256b()
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	for _, faultyCiphertext := range []string{"", "3f07fb18"} {
		plaintext, err := DecryptChaCha20(faultyCiphertext, key)
		assert.Equal(t, "", plaintext)
		assert.Contains(t, err.Error(), "DecryptChaCha20: ciphertext too short with length")
	}
}

func Test_DecryptChaCha20_InvalidCiphertext(t *testing.T) {
	// Want: respond with encryption/decryption error
	keyForEncrypt, err := Key256b()
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	differentKey, err := Key256b()
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	faultyCiphertext1 := "b4e30671a3ddca44201d4a6998f315f38010441d41eb72dad55070cd133e111d2520407b4791bab0092417dd7b3a58303606afe23ae331c31e6c9983db17e06c"
	faultyCiphertext2, err := EncryptChaCha20("some-plain-text", keyForEncrypt)

	for _, faultyCiphertext := range []string{faultyCiphertext1, faultyCiphertext2} {
		plaintext, err := DecryptChaCha20(faultyCiphertext, differentKey)
		assert.Equal(t, "", plaintext)
		assert.Contains(t, err.Error(), "DecryptChaCha20: failed to decrypt ciphertext with error: [chacha20poly1305: message authentication failed]")
	}
}

func Test_DecryptChaCha20_PositivePath(t *testing.T) {
	// Want: the entire encrypt-decrypt cycle works end-to-end
	originalPlaintext := "some-pretty-important-plaintext"
	key, err := Key256b()
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	ciphertext, err := EncryptChaCha20(originalPlaintext, key)
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	decryptedPlaintext, err := DecryptChaCha20(ciphertext, key)
	assert.Equal(t, originalPlaintext, decryptedPlaintext)
}

// AEAD with Google Cloud Platform KMS
//////////////////////////////////////////////////////////////////////////////////
func Test_EncryptAeadGkms_PositivePath(t *testing.T) {
	// Escape hatch if there is need to operate off-line or in environments that cannot be connected to GCP
	if os.Getenv("DISABLE_GCP_TESTS") == "1" {
		t.Skip("WARNING: GCP related functions tests DISABLED, set DISABLE_GCP_TESTS != 1 to enable them. This means that GCP KMS cryptography code is untested")
	}

	// Want: encryption works end-to-end
	keyName, ok := os.LookupEnv("TEST_GKMS_SYMMETRIC_ENCRYPTION_KEY_RESOURCE_NAME")
	if ok != true {
		t.Fatal("To test this function please set TEST_GKMS_SYMMETRIC_ENCRYPTION_KEY_RESOURCE_NAME environment variable to a valid GKMS resource name, see https://cloud.google.com/kms/docs/creating-keys for details")
	}
	for _, plaintext := range []string{"", "some-text", "ef65a7ac36a5d6c56cd6cd63e8683b9e5f3c8cbdf27650afc257285f75d4bf38209a899dee8348ddb8d49cf00a26f2118fd479b2ae10c8397b4cf52bce342bf3"} {
		ciphertext, err := EncryptAeadGkms(plaintext, keyName)
		if err != nil {
			t.Errorf(err.Error())
		}
		assert.Greater(t, len(ciphertext), 32)
		decryptedCiphertext, err := DecryptAeadGkms(ciphertext, keyName)
		if err != nil {
			t.Errorf(err.Error())
		}
		assert.Equal(t, plaintext, decryptedCiphertext)
	}

	// Want: ciphertext is not deterministic
	plaintext2repeat := "will-be-encrypted-twice"
	ciphertext1, err := EncryptAeadGkms(plaintext2repeat, keyName)
	if err != nil {
		t.Errorf(err.Error())
	}
	ciphertext2, err := EncryptAeadGkms(plaintext2repeat, keyName)
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.NotEqual(t, ciphertext1, ciphertext2)
}

func Test_DecryptAeadGkms_PositivePath(t *testing.T) {
	// Escape hatch if there is need to operate off-line or in environments that cannot be connected to GCP
	if os.Getenv("DISABLE_GCP_TESTS") == "1" {
		t.Skip("WARNING: GCP related functions tests DISABLED, set DISABLE_GCP_TESTS != 1 to enable them. This means that GCP KMS cryptography code is untested")
	}

	// Want: the entire encrypt-decrypt cycle works end-to-end
	originalPlaintext := "some-pretty-important-plaintext"
	keyName, ok := os.LookupEnv("TEST_GKMS_SYMMETRIC_ENCRYPTION_KEY_RESOURCE_NAME")
	if ok != true {
		t.Fatal("To test this function please set TEST_GKMS_SYMMETRIC_ENCRYPTION_KEY_RESOURCE_NAME environment variable to a valid GKMS resource name, see https://cloud.google.com/kms/docs/creating-keys for details")
	}
	ciphertext, err := EncryptAeadGkms(originalPlaintext, keyName)
	if err != nil {
		t.Fatal(err.Error()) // No need to continue if failed at this point
	}
	decryptedPlaintext, err := DecryptAeadGkms(ciphertext, keyName)
	assert.Equal(t, originalPlaintext, decryptedPlaintext)
}

// Generic functions
//////////////////////////////////////////////////////////////////////////////////
func Test_Key128b(t *testing.T) {
	// Want: the function generates a 256-bit key
	key, err := Key128b()
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Equal(t, 16, len([]byte(key)))
}

func Test_Key256b(t *testing.T) {
	// Want: the function generates a 256-bit key
	key, err := Key256b()
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Equal(t, 32, len([]byte(key)))
}

func Test_Key512b(t *testing.T) {
	// Want: the function generates a 256-bit key
	key, err := Key512b()
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Equal(t, 64, len([]byte(key)))
}

func Test_KeyChaCha20(t *testing.T) {
	// Want: the function generates a 256-bit key
	key, err := KeyChaCha20()
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Equal(t, 32, len([]byte(key)))
}

func Test_RandomHex(t *testing.T) {
	// Want: the function generates output of the desired size
	expectedLengthInBytes := 20
	str, err := RandomHex(expectedLengthInBytes)
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Equal(t, expectedLengthInBytes, len([]byte(str))/2) // Note: 1 byte == 2 hex digits, e.g. 0x11
}

func Test_Sha256Digest(t *testing.T) {
	// Want: the function provides a deterministic digest
	message := "People who live far below their means enjoy a freedom that people busy upgrading their lifestyles can't fathom"
	digestOne := Sha256Digest(message)
	digestTwo := Sha256Digest(message)
	assert.Equal(t, 64, len(digestOne))
	assert.Equal(t, digestOne, digestTwo)
}
