package cryptography

import (
	kms "cloud.google.com/go/kms/apiv1"
	"context"
	"crypto"
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
)

// RSA PKCS1v15 - native
//////////////////////////////////////////////////////////////////////////////////

// SingRsa issues RSA PKCS1v15 digital signatures using a PEM formated private key
func SignRsaPKCS1v15(message string, privateKeyPem string) (string, error) {
	// Convert plaintext message into bytes
	messageBytes := []byte(message)

	// Parse the key
	rsaPrivateKey, err := RsaPrivateKeyFromPemStr(privateKeyPem)
	if err != nil {
		return "", fmt.Errorf("SignRsaPKCS1v15 failed to parse private key: [%w]", err)
	}

	// Create a hash from the message
	hashedMessage := sha256.Sum256(messageBytes)

	// Sign the hashed message
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, hashedMessage[:])
	if err != nil {
		return "", fmt.Errorf("SignRsaPKCS1v15 failed to sign message with error: [%w]", err)
	}
	// Encode to hex
	hexEncodedSignature := hex.EncodeToString(signature)
	return hexEncodedSignature, nil
}

// VerifyRsaPKCS1v15 checks the validity of RSA PKCS1v15 digital signatures using a PEM formated public key
func VerifyRsaPKCS1v15(message string, signatureHex string, publicKeyPem string) error {
	// Convert plaintext message into bytes
	messageBytes := []byte(message)

	// Decode the hex key into bytes
	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("VerifyRsaPKCS1v15 failed to convert signature hex string to bytes: [%w]", err)
	}

	// Parse the key
	rsaPublicKey, err := RsaPublicKeyFromPemStr(publicKeyPem)
	if err != nil {
		return fmt.Errorf("VerifyRsaPKCS1v15 failed to parse public key: [%w]", err)
	}

	// Create a hash from the message
	hashedMessage := sha256.Sum256(messageBytes)

	// Verify the signature
	var verificationError error
	verificationError = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hashedMessage[:], signatureBytes)
	if verificationError != nil {
		return fmt.Errorf("VerifyRsaPKCS1v15 signature verification failed with error: [%w]", verificationError)
	}
	return nil
}

// RSA PSS native
//////////////////////////////////////////////////////////////////////////////////

// SingRsaPss issues RSA PSS digital signatures using a PEM formated private key
func SignRsaPss(message string, privateKeyPem string) (string, error) {
	// Convert plaintext message into bytes
	messageBytes := []byte(message)

	// Parse the key
	rsaPrivateKey, err := RsaPrivateKeyFromPemStr(privateKeyPem)
	if err != nil {
		return "", fmt.Errorf("SignRsaPss failed to parse private key: [%w]", err)
	}

	// Create a hash from the message
	hashedMessage := sha256.Sum256(messageBytes)

	// Sign the hashed message
	signature, err := rsa.SignPSS(rand.Reader, rsaPrivateKey, crypto.SHA256, hashedMessage[:], nil)
	if err != nil {
		return "", fmt.Errorf("SignRsaPss failed to sign message with error: [%w]", err)
	}
	// Encode to hex
	hexEncodedSignature := hex.EncodeToString(signature)
	return hexEncodedSignature, nil
}

// VerifyRsaPss checks the validity of RSA PSS digital signatures using a PEM formated public key
func VerifyRsaPss(message string, signatureHex string, publicKeyPem string) error {
	// Convert plaintext message into bytes
	messageBytes := []byte(message)

	// Decode the hex key into bytes
	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("VerifyRsaPss failed to convert signature hex string to bytes: [%w]", err)
	}

	// Parse the key
	rsaPublicKey, err := RsaPublicKeyFromPemStr(publicKeyPem)
	if err != nil {
		return fmt.Errorf("VerifyRsaPss failed to parse public key: [%w]", err)
	}

	// Create a hash from the message
	hashedMessage := sha256.Sum256(messageBytes)

	// Verify the signature
	var verificationError error
	verificationError = rsa.VerifyPSS(rsaPublicKey, crypto.SHA256, hashedMessage[:], signatureBytes, nil)
	if verificationError != nil {
		return fmt.Errorf("VerifyRsaPss signature verification failed with error: [%w]", verificationError)
	}
	return nil
}

// RSA PKCS1v15, RSA PSS and ECDSA via Google Cloud Platform KMS API
//////////////////////////////////////////////////////////////////////////////////

// SignGkms issues a hex encoded digitgal signature using the GKMS API.
//
// Supported algorithms are RSA-PSS, RSA PKCS and ECDSA, see details on https://cloud.google.com/kms/docs/algorithms.
// Which algorithm is used is dictated by the type of the key used for the singing operation.
func SignGkms(message string, privateKeyName string) (string, error) {
	// Create client
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return "", fmt.Errorf("SignGkms failed to create kms client: [%w]", err)
	}
	defer client.Close()

	// Convert message into bytes
	plaintext := []byte(message)

	// Calculate message digest
	digest := sha256.New()
	if _, err := digest.Write(plaintext); err != nil {
		return "", fmt.Errorf("SignGkms failed to create digest: [%w]", err)
	}

	// Calculate checksum
	digestCRC32C := Checksum(digest.Sum(nil))

	// Build the signing request
	req := &kmspb.AsymmetricSignRequest{
		Name: privateKeyName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest.Sum(nil),
			},
		},
		DigestCrc32C: wrapperspb.Int64(int64(digestCRC32C)),
	}

	// Call the API
	result, err := client.AsymmetricSign(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to sign digest: %w", err)
	}
	if result.VerifiedDigestCrc32C == false {
		return "", fmt.Errorf("AsymmetricSign: request corrupted in-transit")
	}
	if int64(Checksum(result.Signature)) != result.SignatureCrc32C.Value {
		return "", fmt.Errorf("AsymmetricSign: response corrupted in-transit")
	}
	// Convert the signature to hex-encoded string
	hexEncodedSignature := hex.EncodeToString(result.Signature)
	return hexEncodedSignature, nil
}

// VerifySignatureGkms checks the validity of a digital signature using the GKMS API
//
// Supported algorithms are RSA-PSS, RSA PKCS and ECDSA, see details on https://cloud.google.com/kms/docs/algorithms.
// Which algorithm is used is dictated by the type of the key used for the signing operation.
func VerifySignatureGkms(message string, signatureHex string, publicKeyPem string) error {
	// Parse the key
	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("VerifySignatureGkms failed decode PEM block containing public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("VerifySignatureGkms failed to parse public key: [%w]", err)
	}
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not rsa")
	}
	return verifyRsaSignatureGkms(message, signatureHex, rsaKey)
}

// verifyRsaSignatureGkms checks the validity of a digital signature using the GKMS API
func verifyRsaSignatureGkms(message string, signatureHex string, rsaKey *rsa.PublicKey) error {
	// Create client
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return fmt.Errorf("verifyRsaSignatureGkms failed to create kms client: [%w]", err)
	}
	defer client.Close()
	// Convert the signature to bytes
	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("verifyRsaSignatureGkms failed to convert signature hex string to bytes: [%w]", err)
	}

	// Verify the signature
	digest := sha256.Sum256([]byte(message))
	if err := rsa.VerifyPSS(rsaKey, crypto.SHA256, digest[:], signatureBytes, &rsa.PSSOptions{
		SaltLength: len(digest),
		Hash:       crypto.SHA256,
	}); err != nil {
		return fmt.Errorf("verifyRsaSignatureGkms failed to verify signature: [%w]", err)
	}
	return nil
}
