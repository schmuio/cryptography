package cryptography

import (
	kms "cloud.google.com/go/kms/apiv1"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"hash/crc32"
)

// Envelope is 
type Envelope struct {
	Ciphertext string
	EncryptedSymmetricKey string
}


// EncryptRsa performs RSA OAEP public key encryption using a key in PEM format
func EncryptRsa(plainText string, puplicKeyPem string) (string, error) {
	// Parse the key
	rsaKey, err := RsaPublicKeyFromPemStr(puplicKeyPem)
	if err != nil {
		return "", fmt.Errorf("EncryptRsa failed to parse public key with error: [%w]", err)
	}
	return encryptRsa(plainText, rsaKey)
}

// encryptRsa performs RSA OAEP encryption using the standard Go crypto/rsa package. This function is
// shared by EncryptRsa and EncryptRsaGkms as the latter differ only in the way they receive their
// public encryption key
func encryptRsa(message string, rsaKey *rsa.PublicKey) (string, error) {
	plaintext := []byte(message)
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, plaintext, nil)
	if err != nil {
		return "", fmt.Errorf("encryptRsa: rsa.EncryptOAEP: [%w]", err)
	}
	hexEncodedCiphertext := hex.EncodeToString(ciphertext)
	return hexEncodedCiphertext, nil
}

// DecryptRsa performs RSA OAEP asymmetric decryption
// using a key in PEM format. It implements the reverse
// operation of EncryptRsa
func DecryptRsa(ciphertextHex string, privateKeyPem string) (string, error) {
	// Convert plaintext message into bytes
	ciphertextBytes, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("DecryptRsa failed to convert ciphertext hex string to bytes: [%w], function expects a a hex-encoded ciphertext string", err)
	}
	// Parse the key
	rsaKey, err := RsaPrivateKeyFromPemStr(privateKeyPem)
	if err != nil {
		return "", fmt.Errorf("DecryptRsa failed to parse private key: [%w]", err)
	}
	// Decrypt message
	decryptedPlainTextBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("DecryptRsa: rsa.DecryptOAEP: [%w]", err)
	}
	return string(decryptedPlainTextBytes), nil
}

// EncryptRsaGkms performs RSA OAEP encryption with the Google Cloud Platform's KMS service (https://cloud.google.com/kms/docs/encrypt-decrypt-rsa).
// privateKeyName: format "projects/my-project/locations/europe/keyRings/my-keyring/cryptoKeys/my-key-name/cryptoKeyVersions/1".
//
// The function uses Google's recommended way of operating with the GCP KMS encryption service and its inclusion here
// is intended to provide convenience to the developer from having multiple cryptographic tools in one place.
//
// Notes:
// - The private key is requested as a parameter because the function will derive the public key from the private one on the fly. Alternatively,
// you can store the public key (e.g. as an environment variable) and use DecryptRsa instead. This would add an extra variable to manage but would
// spare an extra call to the GKMS API on each encryption case.
// - Using this function has a main advantage that the private key value is never exposed and is handled securely by the
// GCP KMS service. The downside is that it binds you to a particular cloud provider as well as it has a minor
// but still non-zero cost per key and per an encryption/decryption operation.
func EncryptRsaGkms(ciphertextHex string, privateKeyName string) (string, error) {
	// Get the key from GKMS
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return "", fmt.Errorf("EncryptRsaGkms failed to create kms client with error: [%w]", err)
	}
	defer client.Close()
	response, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: privateKeyName,
	})
	if err != nil {
		return "", fmt.Errorf("EncryptRsaGkms failed to get public key: [%w]", err)
	}

	// Parse the key
	block, _ := pem.Decode([]byte(response.Pem))
	if block == nil {
		return "", errors.New("EncryptRsaGkms failed decode PEM block containing public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("EncryptRsaGkms failed to parse public key with error: [%w]", err)
	}
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("EncryptRsaGkms public key is not rsa")
	}

	// Once the public key is retrieved, the remaining process is identical to the one implemented in the Go native crypto/rsa package
	return encryptRsa(ciphertextHex, rsaKey)
}

// DecryptRsaGkms performs RSA OAEP decryption with the Google Cloud Platform's KMS service (https://cloud.google.com/kms/docs/encrypt-decrypt-rsa).
// privateKeyName: format "projects/my-project/locations/europe/keyRings/my-keyring/cryptoKeys/my-key-name/cryptoKeyVersions/1".
//
// The function uses Google's recommended way of operating with the GCP KMS encryption service and its inclusion here
// is intended to provide convenience to the developer from having multiple cryptographic tools in one place.
func DecryptRsaGkms(ciphertextHex string, privateKeyName string) (string, error) {
	// Create a client
	ctx := context.Background()
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return "", fmt.Errorf("DecryptRsaGkms failed to create kms client: [%w]", err)
	}
	defer kmsClient.Close()

	// Convert ciphertext to bytes
	ciphertextBytes, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("DecryptRsaGkms failed to convert ciphertext hex string to bytes: [%w], function expects hex-encoded ciphertext", err)
	}

	// Calculate checksum
	ciphertextCRC32C := Checksum(ciphertextBytes)

	// Build the request.
	req := &kmspb.AsymmetricDecryptRequest{
		Name:             privateKeyName,
		Ciphertext:       ciphertextBytes,
		CiphertextCrc32C: wrapperspb.Int64(int64(ciphertextCRC32C)),
	}

	// Call the API.
	result, err := kmsClient.AsymmetricDecrypt(ctx, req)
	if err != nil {
		return "", fmt.Errorf("DecryptRsaGkms failed to decrypt ciphertext: [%w]", err)
	}

	// Verify the checksum
	if result.VerifiedCiphertextCrc32C == false {
		return "", fmt.Errorf("AsymmetricDecrypt: request corrupted in-transit")
	}
	if int64(Checksum(result.Plaintext)) != result.PlaintextCrc32C.Value {
		return "", fmt.Errorf("AsymmetricDecrypt: response corrupted in-transit")
	}
	plaintText := string(result.Plaintext)
	return plaintText, nil
}

// RsaKeyPair a pair of RSA keys
func RsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privatekey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key with error: %w", err)
	}
	return privatekey, &privatekey.PublicKey, nil
}

// RsaKeyPair a pair of RSA keys in PEM format
func RsaKeyPairPem() (string, string, error) {
	privateKey, publicKey, err := RsaKeyPair()
	if err != nil {
		return "", "", fmt.Errorf("RsaKeyPairPem failed to generate key pair with error: [%w]", err)
	}
	privateKeyPem := RsaPrivateKeyAsPemStr(privateKey)
	publicKeyPem, err := RsaPublicKeyAsPemStr(publicKey)
	if err != nil {
		return "", "", fmt.Errorf("RsaKeyPairPem failed to convert public key into PEM string with error: [%w]", err)
	}
	return privateKeyPem, publicKeyPem, nil
}

// RsaPrivateKeyAsPemStr converts an *rsa.PrivateKey into PEM formatted one
func RsaPrivateKeyAsPemStr(privatekey *rsa.PrivateKey) string {
	privatekeyBytes := x509.MarshalPKCS1PrivateKey(privatekey)
	privatekeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privatekeyBytes,
		},
	)
	return string(privatekeyPem)
}

// RsaPrivateKeyFromPemStr converts a PEM formated RSA private key into an *rsa.PrivateKey
func RsaPrivateKeyFromPemStr(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block into *rsa.PrivateKey")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key with error: %w", err)
	}
	return privateKey, nil
}

// RsaPublicKeyAsPemStr converts an *rsa.PublicKey into a PEM formatted one
func RsaPublicKeyAsPemStr(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to export public key with error: %w", err)
	}
	publicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)
	return string(publicKeyPem), nil
}

// RsaPublicKeyFromPemStr converts a PEM formated RSA public key into *rsa.PublicKey
func RsaPublicKeyFromPemStr(publicKeyPem string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate public key with error: %w", err)
	}
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not rsa")
	}
	return rsaKey, nil
}

// PublicKeyPemFromPrivateKeyPem gets the PEM formated RSA public key from the respective PEM formated private key
func PublicKeyPemFromPrivateKeyPem(privateKeyPem string) (string, error) {
	privateKey, err := RsaPrivateKeyFromPemStr(privateKeyPem)
	if err != nil {
		return "", err
	}
	publicKey := &privateKey.PublicKey
	publicKeyPem, err := RsaPublicKeyAsPemStr(publicKey)
	if err != nil {
		return "", err
	}
	return publicKeyPem, nil
}

// PublicRsaKeyFromPrivateKeyName creates an *rsa.Publickey from an GCP KMS RSA private key referenced by [privateKeyName]
func PublicRsaKeyFromPrivateKeyName(privateKeyName string) (*rsa.PublicKey, error) {
	// Create a client
	ctx := context.Background()
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create kms client: %w", err)
	}
	defer kmsClient.Close()

	// Get the public key from the private key
	response, err := kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: privateKeyName})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Parse the public RSA key
	block, _ := pem.Decode([]byte(response.Pem))
	if block == nil {
		return nil, errors.New("PublicRsaKeyFromPrivateKeyName failed decode PEM block containing public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not rsa")
	}
	return rsaKey, nil
}

// Checksum calculates a crc32 digest of a message
func Checksum(message []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(message, t)
}
