package cryptography

import (
	"github.com/stretchr/testify/assert"
	"os"
	"reflect"
	"testing"
)

// RSA OAEP - native
//////////////////////////////////////////////////////////////////////////////////

func Test_EncryptRsa_FaultyKey(t *testing.T) {
	// Want: fail to process returning the expected error message (no panic events or unexpected behavior)
	for _, faultyKey := range []string{"", "not-a-key"} {
		ciphertext, err := EncryptRsa("plaintext", faultyKey)
		assert.Equal(t, "", ciphertext)
		assert.Contains(t, err.Error(), "EncryptRsa failed to parse public key with error: [failed to parse PEM block containing the key]")
	}
}

func Test_EncryptRsa_TooLongInput(t *testing.T) {
	// Want: fail to process returning the expected error message (no panic events or unexpected behavior)
	tooLongPlaintext, err := RandomHex(512)
	if err != nil {
		t.Fatal(err.Error())
	}
	_, publicKey, err := RsaKeyPair()
	if err != nil {
		t.Fatal(err.Error())
	}
	publicKeyPem, err := RsaPublicKeyAsPemStr(publicKey)
	if err != nil {
		t.Fatal(err.Error())
	}

	ciphertext, err := EncryptRsa(tooLongPlaintext, publicKeyPem)
	assert.Equal(t, "", ciphertext)
	assert.Contains(t, err.Error(), "encryptRsa: rsa.EncryptOAEP: [crypto/rsa: message too long for RSA public key size]")
}

func Test_EncryptRsa_PositivePath(t *testing.T) {
	// Want: encryption is successful and encryption is not deterministic
	_, publicKey, err := RsaKeyPair()
	if err != nil {
		t.Fatal(err.Error())
	}
	publicKeyPem, err := RsaPublicKeyAsPemStr(publicKey)
	if err != nil {
		t.Fatal(err.Error())
	}
	for _, plaintext := range []string{"", "some-plaintext", "d9928aee3c7f70403df5e2dd6ab109932b3e7c3d0fd800db3775115426ec31a68ccd9182a8b02c9ae3bc03d552081d19603c9073b2e6001b1a34df5a111d961e287422a9f973902ea5aa6bdf972a71c5da676caa8c5aabaf14ade9e1436526af5045ef433ab34462b7b661f15ab3fde39201a5a3cc5ee417c1bfb9cc6867241f"} {
		ciphertext1, err := EncryptRsa(plaintext, publicKeyPem)
		if err != nil {
			t.Fatal(err.Error())
		}
		ciphertext2, err := EncryptRsa(plaintext, publicKeyPem)
		if err != nil {
			t.Fatal(err.Error())
		}
		assert.Greater(t, len(ciphertext1), 128)
		assert.NotEqual(t, ciphertext1, ciphertext2)
	}
}

func Test_encryptRsa_TooLongInput(t *testing.T) {
	// Want: fail to process returning the expected error message (no panic events or unexpected behavior)
	tooLongPlaintext, err := RandomHex(512)
	if err != nil {
		t.Fatal(err.Error())
	}
	_, publicKey, err := RsaKeyPair()
	if err != nil {
		t.Fatal(err.Error())
	}

	ciphertext, err := encryptRsa(tooLongPlaintext, publicKey)
	assert.Equal(t, "", ciphertext)
	assert.Contains(t, err.Error(), "rsa.EncryptOAEP: [crypto/rsa: message too long for RSA public key size]")
}

func Test_encryptRsa_PositivePath(t *testing.T) {
	// Want: encryption is successful and encryption is not deterministic
	_, publicKey, err := RsaKeyPair()
	if err != nil {
		t.Fatal(err.Error())
	}
	for _, plaintext := range []string{"", "some-plaintext", "d9928aee3c7f70403df5e2dd6ab109932b3e7c3d0fd800db3775115426ec31a68ccd9182a8b02c9ae3bc03d552081d19603c9073b2e6001b1a34df5a111d961e287422a9f973902ea5aa6bdf972a71c5da676caa8c5aabaf14ade9e1436526af5045ef433ab34462b7b661f15ab3fde39201a5a3cc5ee417c1bfb9cc6867241f"} {
		ciphertext1, err := encryptRsa(plaintext, publicKey)
		if err != nil {
			t.Fatal(err.Error())
		}
		ciphertext2, err := encryptRsa(plaintext, publicKey)
		if err != nil {
			t.Fatal(err.Error())
		}
		assert.Greater(t, len(ciphertext1), 128)
		assert.NotEqual(t, ciphertext1, ciphertext2)
	}
}

func Test_DecryptRsa_FaultyKey(t *testing.T) {
	// Want: fail to process returning the expected error message (no panic events or unexpected behavior)
	_, publicKey, err := RsaKeyPair()
	if err != nil {
		t.Fatal(err.Error())
	}
	publicKeyPem, err := RsaPublicKeyAsPemStr(publicKey)
	if err != nil {
		t.Fatal(err.Error())
	}
	ciphertext, err := EncryptRsa("plaintext", publicKeyPem)
	if err != nil {
		t.Fatal(err.Error())
	}
	for _, faultyKey := range []string{"", "not-a-key"} {
		decryptedPlaintext, err := DecryptRsa(ciphertext, faultyKey)
		assert.Equal(t, "", decryptedPlaintext)
		assert.Contains(t, err.Error(), "DecryptRsa failed to parse private key: [failed to parse PEM block into *rsa.PrivateKey]")
	}
}

func Test_DecryptRsa_PositivePath(t *testing.T) {
	// Want: encryption/decryption works end to end
	privateKey, publicKey, err := RsaKeyPair()
	if err != nil {
		t.Fatal(err.Error())
	}
	privateKeyPem := RsaPrivateKeyAsPemStr(privateKey)
	publicKeyPem, err := RsaPublicKeyAsPemStr(publicKey)
	if err != nil {
		t.Fatal(err.Error())
	}
	for _, plaintext := range []string{"", "some-plaintext", "d9928aee3c7f70403df5e2dd6ab109932b3e7c3d0fd800db3775115426ec31a68ccd9182a8b02c9ae3bc03d552081d19603c9073b2e6001b1a34df5a111d961e287422a9f973902ea5aa6bdf972a71c5da676caa8c5aabaf14ade9e1436526af5045ef433ab34462b7b661f15ab3fde39201a5a3cc5ee417c1bfb9cc6867241f"} {
		ciphertext, err := EncryptRsa(plaintext, publicKeyPem)
		if err != nil {
			t.Fatal(err.Error())
		}
		decryptedPlaintext, err := DecryptRsa(ciphertext, privateKeyPem)
		if err != nil {
			t.Fatal(err.Error())
		}
		assert.Equal(t, plaintext, decryptedPlaintext)
	}
}

func Test_DecryptRsa_NegativePath(t *testing.T) {
	// Want: decryption fails on incorrect key or incorrect ciphertext with the expected error
	privateKey, publicKey, err := RsaKeyPair()
	if err != nil {
		t.Fatal(err.Error())
	}
	privateKeyPem := RsaPrivateKeyAsPemStr(privateKey)
	publicKeyPem, err := RsaPublicKeyAsPemStr(publicKey)
	if err != nil {
		t.Fatal(err.Error())
	}

	_, notTheRightPublicKey, err := RsaKeyPair()
	notTheRightPublicKeyPem, err := RsaPublicKeyAsPemStr(notTheRightPublicKey)
	if err != nil {
		t.Fatal(err.Error())
	}

	for _, plaintext := range []string{"", "some-plaintext", "d9928aee3c7f70403df5e2dd6ab109932b3e7c3d0fd800db3775115426ec31a68ccd9182a8b02c9ae3bc03d552081d19603c9073b2e6001b1a34df5a111d961e287422a9f973902ea5aa6bdf972a71c5da676caa8c5aabaf14ade9e1436526af5045ef433ab34462b7b661f15ab3fde39201a5a3cc5ee417c1bfb9cc6867241f"} {
		ciphertext, err := EncryptRsa(plaintext, notTheRightPublicKeyPem)
		if err != nil {
			t.Fatal(err.Error())
		}
		decryptedPlaintext, err := DecryptRsa(ciphertext, privateKeyPem)
		assert.Equal(t, "", decryptedPlaintext)
		assert.Contains(t, err.Error(), "DecryptRsa: rsa.DecryptOAEP: [crypto/rsa: decryption error]")

		ciphertext, err = EncryptRsa(plaintext, publicKeyPem)
		if err != nil {
			t.Fatal(err.Error())
		}
		decryptedPlaintext, err = DecryptRsa(ciphertext+"aa", privateKeyPem)
		assert.Equal(t, "", decryptedPlaintext)
		assert.Contains(t, err.Error(), "DecryptRsa: rsa.DecryptOAEP: [crypto/rsa: decryption error]")
	}
}

// RSA OAEP - Google Cloud Platform KMS
//////////////////////////////////////////////////////////////////////////////////

func Test_EncryptRsaGkms(t *testing.T) {
	// Escape hatch if there is need to operate off-line or in environments that cannot be connected to GCP
	if os.Getenv("DISABLE_GCP_TESTS") == "1" {
		t.Skip("WARNING: GCP related functions tests DISABLED, set DISABLE_GCP_TESTS != 1 to enable them. This means that GCP KMS cryptography code is untested")
	}

	// Want: encryption is successful and encryption is not deterministic
	privateKeyName, ok := os.LookupEnv("TEST_GKMS_RSA_ENCRYPTION_PRIVATE_KEY_RESOURCE_NAME")
	if ok != true {
		t.Fatal("To test this function please set TEST_GKMS_RSA_ENCRYPTION_PRIVATE_KEY_RESOURCE_NAME environment variable to a valid GKMS resource name, see https://cloud.google.com/kms/docs/creating-keys for details")
	}
	for _, plaintext := range []string{"", "some-plaintext", "d9928aee3c7f70403df5e2dd6ab109932b3e7c3d0fd800db3775115426ec31a68ccd9182a8b02c9ae3bc03d552081d19603c9073b2e6001b1a34df5a111d961e287422a9f973902ea5aa6bdf972a71c5da676caa8c5aabaf14ade9e1436526af5045ef433ab34462b7b661f15ab3fde39201a5a3cc5ee417c1bfb9cc6867241f"} {
		ciphertext1, err := EncryptRsaGkms(plaintext, privateKeyName)
		if err != nil {
			t.Fatal(err.Error())
		}
		ciphertext2, err := EncryptRsaGkms(plaintext, privateKeyName)
		if err != nil {
			t.Fatal(err.Error())
		}
		assert.Greater(t, len(ciphertext1), 128)
		assert.NotEqual(t, ciphertext1, ciphertext2)
	}
}

func Test_DecryptRsaGKMS_PositivePath(t *testing.T) {
	// Escape hatch if there is need to operate off-line or in environments that cannot be connected to GCP
	if os.Getenv("DISABLE_GCP_TESTS") == "1" {
		t.Skip("WARNING: GCP related functions tests DISABLED, set DISABLE_GCP_TESTS != 1 to enable them. This means that GCP KMS cryptography code is untested")
	}

	// Want: encryption/decryption works end to end
	privateKeyName, ok := os.LookupEnv("TEST_GKMS_RSA_ENCRYPTION_PRIVATE_KEY_RESOURCE_NAME")
	if ok != true {
		t.Fatal("To test this function please set TEST_GKMS_RSA_ENCRYPTION_PRIVATE_KEY_RESOURCE_NAME environment variable to a valid GKMS resource name, see https://cloud.google.com/kms/docs/creating-keys for details")
	}
	for _, plaintext := range []string{"", "some-plaintext", "d9928aee3c7f70403df5e2dd6ab109932b3e7c3d0fd800db3775115426ec31a68ccd9182a8b02c9ae3bc03d552081d19603c9073b2e6001b1a34df5a111d961e287422a9f973902ea5aa6bdf972a71c5da676caa8c5aabaf14ade9e1436526af5045ef433ab34462b7b661f15ab3fde39201a5a3cc5ee417c1bfb9cc6867241f"} {
		ciphertext, err := EncryptRsaGkms(plaintext, privateKeyName) // The public key is retrieved from the private one
		if err != nil {
			t.Fatal(err.Error())
		}
		decryptedPlaintext, err := DecryptRsaGkms(ciphertext, privateKeyName)
		if err != nil {
			t.Fatal(err.Error())
		}
		assert.Equal(t, plaintext, decryptedPlaintext)
	}
}

func Test_DecryptRsaGKMS_NegativePath(t *testing.T) {
	// Escape hatch if there is need to operate off-line or in environments that cannot be connected to GCP
	if os.Getenv("DISABLE_GCP_TESTS") == "1" {
		t.Skip("WARNING: GCP related functions tests DISABLED, set DISABLE_GCP_TESTS != 1 to enable them. This means that GCP KMS cryptography code is untested")
	}

	// Want: decryption fails incorrect ciphertext with the expected error
	privateKeyName, ok := os.LookupEnv("TEST_GKMS_RSA_ENCRYPTION_PRIVATE_KEY_RESOURCE_NAME")
	if ok != true {
		t.Fatal("To test this function please set TEST_GKMS_RSA_ENCRYPTION_PRIVATE_KEY_RESOURCE_NAME environment variable to a valid GKMS resource name, see https://cloud.google.com/kms/docs/creating-keys for details")
	}
	for _, plaintext := range []string{"", "some-plaintext", "d9928aee3c7f70403df5e2dd6ab109932b3e7c3d0fd800db3775115426ec31a68ccd9182a8b02c9ae3bc03d552081d19603c9073b2e6001b1a34df5a111d961e287422a9f973902ea5aa6bdf972a71c5da676caa8c5aabaf14ade9e1436526af5045ef433ab34462b7b661f15ab3fde39201a5a3cc5ee417c1bfb9cc6867241f"} {
		ciphertext, err := EncryptRsaGkms(plaintext, privateKeyName) // The public key is retrieved from the private one
		if err != nil {
			t.Fatal(err.Error())
		}
		decryptedPlaintext, err := DecryptRsaGkms(ciphertext+"aa", privateKeyName)
		assert.Equal(t, "", decryptedPlaintext)
		assert.Contains(t, err.Error(), "ecryptRsaGkms failed to decrypt ciphertext")
	}
}

// Envelope Encryption
//////////////////////////////////////////////////////////////////////////////////

func TestEnvelopeEncryptAes_InvalidAsymmetricKey(t *testing.T) {
	// Want: function does not panic and returns the expected errors
	_, _, err := EnvelopeEncryptAes("some-plaintext", "")
	assert.Contains(t, err.Error(), "EnvelopeEncrypt failed to encrypt ephemeral key with error: [EncryptRsa failed to parse public key with error: [failed to parse PEM block containing the key]]")

	_, _, err = EnvelopeEncryptAes("some-plaintext", "invalid-key-format")
	assert.Contains(t, err.Error(), "EnvelopeEncrypt failed to encrypt ephemeral key with error: [EncryptRsa failed to parse public key with error: [failed to parse PEM block containing the key]]")
}

func TestEnvelopeEncryptAes_PositivePath(t *testing.T) {
	// Want: encryption works end to end
	privateKey, publicKey, err := RsaKeyPairPem()
	if err != nil {
		t.Fatal(err.Error())
	}
	plaintext := "some-pretty-important-plaintext"
	ciphertext, encSymKey, err := EnvelopeEncryptAes(plaintext, publicKey)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Want: the symmetric key is decryptable with the private asymmetric key
	symKey, err := DecryptRsa(encSymKey, privateKey)
	if err != nil {
		t.Fatal(err.Error())
	}
	assert.Equal(t, 32, len(symKey))

	// Want: ciphertext is decryptable by symKey
	decryptedCiphertext, err := DecryptAesGcm(ciphertext, symKey)
	if err != nil {
		t.Fatal(err.Error())
	}
	assert.Equal(t, plaintext, decryptedCiphertext)
}

func TestEnvelopeDecryptAes_OnIncorrectKey(t *testing.T) {
	// Want: function does not panic and returns the expected errors
	_, publicKey, err := RsaKeyPairPem()
	if err != nil {
		t.Fatal(err.Error())
	}
	theWrongPrivateKey, _, err := RsaKeyPairPem()
	if err != nil {
		t.Fatal(err.Error())
	}
	plaintext := "some-pretty-important-plaintext"
	ciphertext, encSymKey, err := EnvelopeEncryptAes(plaintext, publicKey)
	if err != nil {
		t.Fatal(err.Error())
	}

	decryptedCiphertext, err := EnvelopeDecryptAes(ciphertext, encSymKey, theWrongPrivateKey)
	assert.Equal(t, "", decryptedCiphertext)
	assert.Contains(t, err.Error(), "DecryptRsa: rsa.DecryptOAEP: [crypto/rsa: decryption error]")

	decryptedCiphertext, err = EnvelopeDecryptAes(ciphertext, encSymKey, "")
	assert.Equal(t, "", decryptedCiphertext)
	assert.Contains(t, err.Error(), "failed to parse PEM block into *rsa.PrivateKey")
}

func TestEnvelopeDecryptAes_PositivePath(t *testing.T) {
	// Want: encryption works end to end
	privateKey, publicKey, err := RsaKeyPairPem()
	if err != nil {
		t.Fatal(err.Error())
	}
	plaintext := "some-pretty-important-plaintext"
	ciphertext, encSymKey, err := EnvelopeEncryptAes(plaintext, publicKey)
	if err != nil {
		t.Fatal(err.Error())
	}
	decryptedCiphertext, err := EnvelopeDecryptAes(ciphertext, encSymKey, privateKey)
	if err != nil {
		t.Fatal(err.Error())
	}
	assert.Equal(t, plaintext, decryptedCiphertext)
}

// Generic functions
//////////////////////////////////////////////////////////////////////////////////

func TestRsaKeyParsers(t *testing.T) {
	privateKey, publicKey, err := RsaKeyPair()
	if err != nil {
		t.Errorf("generating keys failed failed, error: %v", err)
	}

	privateKeyPem := RsaPrivateKeyAsPemStr(privateKey)
	publicKeyPem, err := RsaPublicKeyAsPemStr(publicKey)
	if err != nil {
		t.Errorf("exporting public key failed failed, error: %v", err)
	}

	reconstructedPrivateKey, err := RsaPrivateKeyFromPemStr(privateKeyPem)
	if err != nil {
		t.Errorf("parsing private key failed failed, error: %v", err)
	}
	reconstructedPublicKey, err := RsaPublicKeyFromPemStr(publicKeyPem)
	if err != nil {
		t.Errorf("parsing public key failed failed, error: %v", err)
	}
	if reflect.TypeOf(reconstructedPrivateKey) != reflect.TypeOf(privateKey) {
		t.Errorf("incorrect type of parsed key: %v", reflect.TypeOf(reconstructedPrivateKey))
	}
	if reflect.TypeOf(reconstructedPublicKey) != reflect.TypeOf(publicKey) {
		t.Errorf("incorrect type of parsed key: %v", reflect.TypeOf(reconstructedPublicKey))
	}
	_, err = PublicKeyPemFromPrivateKeyPem(privateKeyPem)
	if err != nil {
		t.Errorf(err.Error())
	}
}

func Test_PublicRsaKeyFromPrivateKeyName(t *testing.T) {
	// Escape hatch if there is need to operate off-line or in environments that cannot be connected to GCP
	if os.Getenv("DISABLE_GCP_TESTS") == "1" {
		t.Skip("WARNING: GCP related functions tests DISABLED, set DISABLE_GCP_TESTS != 1 to enable them. This means that GCP KMS cryptography code is untested")
	}

	// Want: the public key is retrieved and it is convertible to PEM format
	privateKeyName, ok := os.LookupEnv("TEST_GKMS_RSA_ENCRYPTION_PRIVATE_KEY_RESOURCE_NAME")
	if ok != true {
		t.Fatal("To test this function please set TEST_GKMS_RSA_ENCRYPTION_PRIVATE_KEY_RESOURCE_NAME environment variable to a valid GKMS resource name, see https://cloud.google.com/kms/docs/creating-keys for details")
	}
	publicKey, err := PublicRsaKeyFromPrivateKeyName(privateKeyName)
	if err != nil {
		t.Fatal(err.Error())
	}
	_, err = RsaPublicKeyAsPemStr(publicKey)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestRsaKeyPairPem(t *testing.T) {
	// Want: valid PEM-format keys are created
	privateKeyPem, publicKeyPem, err := RsaKeyPairPem()
	if err != nil {
		t.Fatal(err.Error())
	}
	_, err = RsaPrivateKeyFromPemStr(privateKeyPem)
	if err != nil {
		t.Errorf(err.Error())
	}
	_, err = RsaPublicKeyFromPemStr(publicKeyPem)
	if err != nil {
		t.Errorf(err.Error())
	}
}
