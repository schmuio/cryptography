// cryptography provides functions implementing
// commonly needed cryptographic operations - symmetric
// encryption, digital signatures, hashes, time based
// one time passwords. It presents a compact and
// ready-to-go cryptographic toolbox for developers.
//
// The package is intended to step on trustworthy cryptographic
// implementations from the Go standard library and the Google
// Cloud KMS API offering easy to use and intendedly safe cryptographic
// utilities for a broad set of development cases.
//
// Note of caution: please do not try to change the internal
// workings of the functions unless you do know what you are
// doing. If there is a security concern or a recommendation
// it would be warmly welcomed and promtly addressed
package cryptography

import (
	kms "cloud.google.com/go/kms/apiv1"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	chacha "golang.org/x/crypto/chacha20poly1305"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"io"
)

// EncryptAesGcm peforms AES GCM encryption with an explicitly provided encryption/decryption key (as opposed to a pointer/reference to a key)
// The function expects string-type plaintext and key
//
// Note: Do not use this function more than 2^32 with the same key due to the risk
// of repetition and its potentially very serious security implications (see https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=51288#page=29),
// rotate the keys accordingly considering the frequency of encryption operations
func EncryptAesGcm(message string, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("EncryptAesGcm failed to create new block with error: [%w]", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("EncryptAesGcm failed to create new aesgcm with error: [%w]", err)
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("EncryptAesGcm failed to create nonce with error: [%w]", err)
	}
	messageBytes := []byte(message)
	ciphertextBytes := aesgcm.Seal(nonce, nonce, messageBytes, nil)
	ciphertextHex := hex.EncodeToString(ciphertextBytes)
	return ciphertextHex, nil
}

// DecryptAesGcm peforms AES GCM decryption with an explicitly provided encryption/decryption key (as opposed to a pointer/reference to a key).
// It reverses the result of EncryptAesGcm.
//
// Note: the result of EncryptAesGcm is a string containing hexadecimal digits
// so that DecryptAesGcm expects a hex encoded input
func DecryptAesGcm(ciphertextHex string, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("DecryptAesGcm failed to create new block with error: [%w]", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("DecryptAesGcm failed to create new aesgcm with error: [%w]", err)
	}
	ciphertextWithNonceBytes, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("DecryptAesGcm failed to decode ciphertext hex to bytes with error: [%w], ensure ciphertext contains valid hex digits only", err)
	}
	nonceSize := aesgcm.NonceSize()
	if len(ciphertextWithNonceBytes) < nonceSize {
		return "", errors.New("DecryptAesGcm failed to ciphertext - input too short")
	}
	nonce := ciphertextWithNonceBytes[:nonceSize]
	ciphertextBytes := ciphertextWithNonceBytes[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt ciphertext with error: %w", err)
	}
	return string(plaintext), nil
}

// EncryptyChaCha20 performs ChaCha20-poly1305 encryption with an explicitly provided encryption/decryption key (as opposed to a pointer/reference to a key)
// This is an authenticated encryption algorithm that is an alternative to AES GCM (for details see Wong, D., 2001, "Real-World Cryptography")
func EncryptChaCha20(message string, key string) (string, error) {
	aead, err := chacha.NewX([]byte(key))
	if err != nil {
		return "", fmt.Errorf("EncryptChaCha20: failed to create eaed primitive with error: [%w]", err)
	}
	messageBytes := []byte(message)
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(messageBytes)+aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to create nonce with error: [%w]", err)
	}
	// Encrypt the message and append the ciphertext to the nonce.
	encryptedMessageBytes := aead.Seal(nonce, nonce, messageBytes, nil)
	return base64.StdEncoding.EncodeToString(encryptedMessageBytes), nil
}

// DecryptChaCha20 performs ChaCha20-poly1305 decryption with an explicitly provided encryption/decryption key (as opposed to a pointer/reference to a key)
// It reverses the result from EncryptChaCha20
func DecryptChaCha20(ciphertext string, key string) (string, error) {
	// Convert the string ciphertext into bs64 encoded one
	ciphertextBs64, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("DecryptChaCha20: failed to base64 decode string ciphertext with error: [%w], base64 encoded string is expected", err)
	}
	aead, err := chacha.NewX([]byte(key))
	if err != nil {
		return "", fmt.Errorf("DecryptChaCha20: failed to create eaed primitive with error: [%w]", err)
	}

	ciphertextWithNonceBytes := []byte(ciphertextBs64)
	if len(ciphertextWithNonceBytes) < aead.NonceSize() {
		return "", fmt.Errorf("DecryptChaCha20: ciphertext too short with length: [%v]", len(ciphertextWithNonceBytes))
	}
	// Split nonce and ciphertext.
	nonce, ciphertextBytes := ciphertextWithNonceBytes[:aead.NonceSize()], ciphertextWithNonceBytes[aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	plaintext, err := aead.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("DecryptChaCha20: failed to decrypt ciphertext with error: [%w]", err)
	}
	return string(plaintext), nil
}

// EncryptAeadGkms encrypts (AEAD) specified plaintext message with a particular keyName key (specified by keyName),
// using the Google KMS service (https://cloud.google.com/kms/docs/encrypt-decrypt).
// keyName: format "projects/my-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key".
//
// The function uses Google's recommended way of operating with the GCP KMS encryption service and its inclusion here
// is intended to provide convenience to the developer from having multiple cryptographic tools in one place.
//
// Using this function has a main advantage that the key value is never exposed and is handled securely by the
// GCP KMS service. The downside is that it binds you to a particular cloud provider as well as it has a minor
// but still non-zero cost per key and per an encryption/decryption operation.
func EncryptAeadGkms(message string, keyName string) (string, error) {
	// Create a client
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return "", fmt.Errorf("EncryptAeadGkms failed to create kms client: [%w]", err)
	}
	defer client.Close()

	// Convert the message into bytes
	plaintextBytes := []byte(message)

	// Calculate checksum
	plaintextCRC32C := Checksum(plaintextBytes)

	// Build the encrypt request
	request := &kmspb.EncryptRequest{
		Name:            keyName,
		Plaintext:       plaintextBytes,
		PlaintextCrc32C: wrapperspb.Int64(int64(plaintextCRC32C)),
	}

	// Call the API
	encryptionResult, err := client.Encrypt(ctx, request)
	if err != nil {
		return "", fmt.Errorf("EncryptAeadGkms failed to encrypt: %w", err)
	}
	if encryptionResult.VerifiedPlaintextCrc32C == false {
		return "", errors.New("EncryptAeadGkms failed: request corrupted in-transit")
	}
	if int64(Checksum(encryptionResult.Ciphertext)) != encryptionResult.CiphertextCrc32C.Value {
		return "", errors.New("EncryptAeadGkms failed: response corrupted in-transit")
	}

	// Convert the ciphertext into a HEX string
	hexEncodedCiphertext := hex.EncodeToString(encryptionResult.Ciphertext)
	return hexEncodedCiphertext, nil
}

// DecryptAeadGkms decrypts ciphertexts from EncryptAeadGkms with a particular keyName key
// (specified by keyName), using the Google KMS service (https://cloud.google.com/kms/docs/encrypt-decrypt).
// keyName: format "projects/my-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key".
//
// The function uses Google's recommended way of operating with the GCP KMS encryption/decryption service and
// its inclusion here is intended to provide convenience to the developer from having multiple cryptographic
// tools in one place.
//
// Using this function has a main advantage that the key value is never exposed and is handled securely by the
// GCP KMS service. The downside is that it binds you to a particular cloud provider as well as it has a minor
// but still non-zero cost per key and per an encryption/decryption operation.
func DecryptAeadGkms(ciphertextHex string, keyName string) (string, error) {
	// Create a client
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)

	if err != nil {
		return "", fmt.Errorf("DecryptAeadGkms failed to create kms client: %w", err)
	}
	defer client.Close()

	// Convert ciphertext to bytes
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("DecryptAeadGkms failed to convert ciphertext hex string to bytes: %w", err)
	}

	// Compute CRC32 (optional)
	ciphertextCRC32C := Checksum(ciphertext)

	// Build the request
	req := &kmspb.DecryptRequest{
		Name:             keyName,
		Ciphertext:       ciphertext,
		CiphertextCrc32C: wrapperspb.Int64(int64(ciphertextCRC32C)),
	}

	// Call the API
	decryptionResult, err := client.Decrypt(ctx, req)
	if err != nil {
		return "", fmt.Errorf("DecryptAeadGkms failed to decrypt ciphertext: %w", err)
	}

	// Evaluate checksum
	if int64(Checksum(decryptionResult.Plaintext)) != decryptionResult.PlaintextCrc32C.Value {
		return "", errors.New("DecryptAeadGkms failed: response corrupted in-transit")
	}

	// Convert plaintext to string
	plaintText := string(decryptionResult.Plaintext)
	return plaintText, nil
}

// RandomHex generates a random string with hexadecimal digits
func RandomHex(nBytes int) (string, error) {
	randomBytes := make([]byte, nBytes)
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		return "", fmt.Errorf("failed to create key with error: %w", err)
	}
	keyHex := hex.EncodeToString(randomBytes)
	return keyHex, nil
}

// Key128b generates a 128-bit key as HEX-string using a random generator fit for cryptographic purposes
func Key128b() (string, error) {
	return RandomHex(8)
}

// Key256b generates a 256-bit key as HEX-string using a random generator fit for cryptographic purposes
func Key256b() (string, error) {
	return RandomHex(16)
}

// Key512b generates a 512-bit key as HEX-string using a random generator fit for cryptographic purposes
func Key512b() (string, error) {
	return RandomHex(32)
}

// KeyChaCha20 generates a 256-bit key as HEX-string using a random generator fit for cryptographic purposes
func KeyChaCha20() (string, error) {
	return Key256b()
}

// Sha256Digest generates a HEX-encoded message digest
// from a string input
func Sha256Digest(text string) string {
	sha256Digest := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sha256Digest[:])
}
