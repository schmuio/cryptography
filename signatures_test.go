package cryptography

import (
	"crypto/x509"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

// RSA PKCS1v15 - native
//////////////////////////////////////////////////////////////////////////////////

func TestSignAndVerifyRsaPKCS1v15(t *testing.T) {
	privateKeyPem, publicKeyPem, err := RsaKeyPairPem()
	if err != nil {
		t.Fatal(err.Error())
	}
	// Signing
	// Want: successful issuance of a digital signature
	message := "some-message"
	fakeMessage := "fake-message"
	signature, err := SignRsaPKCS1v15(message, privateKeyPem)
	if err != nil {
		t.Fatalf("signing failed with error: %v", err)
	}
	assert.Greater(t, len(signature), 128)

	// Verification
	// Want: successful verification on the right message
	err = VerifyRsaPKCS1v15(message, signature, publicKeyPem)
	if err != nil {
		t.Fatalf("signature verification failed with error: %v", err)
	}

	// Want: verficatin error on incorrect message
	err = VerifyRsaPKCS1v15(fakeMessage, signature, publicKeyPem)
	assert.Contains(t, err.Error(), "signature verification failed with error: [crypto/rsa: verification error]")
}

// RSA PSS - native
//////////////////////////////////////////////////////////////////////////////////

func TestSignAndVerifyRsaPss(t *testing.T) {
	privateKeyPem, publicKeyPem, err := RsaKeyPairPem()
	if err != nil {
		t.Fatal(err.Error())
	}
	// Signing
	// Want: successful issuance of a digital signature
	message := "some-message"
	fakeMessage := "fake-message"
	signature, err := SignRsaPss(message, privateKeyPem)
	if err != nil {
		t.Fatalf("signing failed with error: %v", err)
	}
	assert.Greater(t, len(signature), 128)

	// Verification
	// Want: successful verification on the right message
	err = VerifyRsaPss(message, signature, publicKeyPem)
	if err != nil {
		t.Fatalf("signature verification failed with error: %v", err)
	}

	// Want: verficatin error on incorrect message
	err = VerifyRsaPss(fakeMessage, signature, publicKeyPem)
	assert.Contains(t, err.Error(), "signature verification failed with error: [crypto/rsa: verification error]")
}

// RSA PSS - Google Cloud Platform KMS API
//////////////////////////////////////////////////////////////////////////////////

func TestSignAndVerifyGkms(t *testing.T) {
	// Escape hatch if there is need to operate off-line or in environments that cannot be connected to GCP
	if os.Getenv("DISABLE_GCP_TESTS") == "1" {
		t.Skip("WARNING: GCP related functions tests DISABLED, set DISABLE_GCP_TESTS != 1 to enable them. This means that GCP KMS cryptography code is untested")
	}

	privateKeyName, ok := os.LookupEnv("TEST_GKMS_RSA_SIGN_PRIVATE_KEY_RESOURCE_NAME")
	if ok != true {
		t.Fatal("To test this function please set TEST_GKMS_RSA_SIGN_PRIVATE_KEY_RESOURCE_NAME environment variable to a valid GKMS resource name, see https://cloud.google.com/kms/docs/creating-keys for details")
	}
	publicKeyPem, ok := os.LookupEnv("TEST_GKMS_RSA_SIGN_PUBLIC_KEY_PEM")
	if ok != true {
		t.Fatal("To test this function please set TEST_GKMS_RSA_SIGN_PUBLIC_KEY_PEM environment variable to a valid GKMS resource name, see https://cloud.google.com/kms/docs/creating-keys for details")
	}
	// Signing
	// Want: successful issuance of a digital signature
	message := "some-message"
	fakeMessage := "fake-message"
	signature, err := SignGkms(message, privateKeyName)
	if err != nil {
		t.Fatalf("signing failed with error: %v", err)
	}
	assert.Greater(t, len(signature), 128)
	// Verification
	// Want: successful verification on the right message
	err = VerifySignatureGkms(message, signature, publicKeyPem)
	if err != nil {
		t.Fatalf("signature verification failed with error: %v", err)
	}

	// Want: verfication error on incorrect message
	err = VerifySignatureGkms(fakeMessage, signature, publicKeyPem)
	assert.Contains(t, err.Error(), "[crypto/rsa: verification error]")
}

// ECDSA - native
//////////////////////////////////////////////////////////////////////////////////

func TestEcdsaKeyPair(t *testing.T) {
	// Want: successful generation of a key pair
	privateKey, publicKey, err := EcdsaKeyPair()
	if err != nil {
		t.Errorf(err.Error())
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Equal(t, 242, len(hex.EncodeToString(privateKeyBytes)))
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Equal(t, 182, len(hex.EncodeToString(publicKeyBytes)))
}

func TestEcdsaKeyPairHex(t *testing.T) {
	// Want: successful generation of a key pair
	privateKeyHex, publicKeyHex, err := EcdsaKeyPairHex()
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Equal(t, 242, len(privateKeyHex))
	assert.Equal(t, 182, len(publicKeyHex))
}

func TestEcdsaPrivateKeyFromHex(t *testing.T) {
	// Want: private key is converted from hex to *ecdsa.PrivateKey and back to bytes without errors
	privateKeyHex, _, err := EcdsaKeyPairHex()
	if err != nil {
		t.Errorf(err.Error())
	}
	privateKey, err := EcdsaPrivateKeyFromHex(privateKeyHex)
	if err != nil {
		t.Errorf(err.Error())
	}
	_, err = x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Errorf(err.Error())
	}
}

func TestEcdsaPublicKeyFromHex(t *testing.T) {
	// Want: private key is converted from hex to *ecdsa.PrivateKey and back to bytes without errors
	_, publicKeyHex, err := EcdsaKeyPairHex()
	if err != nil {
		t.Errorf(err.Error())
	}
	publicKey, err := EcdsaPublicKeyFromHex(publicKeyHex)
	if err != nil {
		t.Errorf(err.Error())
	}
	_, err = x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Errorf(err.Error())
	}
}

func TestSignAndVerifyEcdsa(t *testing.T) {
	// Want: signing and verification work end-to-end
	privateKeyHex, publicKeyHex, err := EcdsaKeyPairHex()
	if err != nil {
		t.Errorf(err.Error())
	}
	message := "a-very-important-message"
	signature, err := SignEcdsa(message, privateKeyHex)
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Greater(t, len(signature), 128)
	err = VerifyEcdsa(message, signature, publicKeyHex)
	if err != nil {
		t.Errorf(err.Error())
	}

	// Want: verification failure on a wrong message
	fakeMessage := "this-message-has-been-tempered-with"
	err = VerifyEcdsa(fakeMessage, signature, publicKeyHex)
	if err == nil {
		t.Errorf("should have not verified the signature of a fake message")
	}
	assert.Equal(t, err.Error(), "Singature verification failed")

	// Want: message not verified in case of using the wrong key
	_, anotherPublicKeyHex, err := EcdsaKeyPairHex()
	if err != nil {
		t.Errorf(err.Error())
	}
	err = VerifyEcdsa(message, signature, anotherPublicKeyHex)
	if err == nil {
		t.Errorf("should have not verified the signature with a wrong public key")
	}
	assert.Equal(t, err.Error(), "Singature verification failed")
}
