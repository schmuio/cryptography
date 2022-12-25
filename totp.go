package cryptography

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"image/png"
	"strings"
	"time"
)

// TotpManager is a an entity encapsulating
// all necessary data and methods to support the lifecycle
// of TOTPs (RFC 6238).
//
// Supported hash algorithms are SHA256, SHA512 as well as SHA1.
// See caveats about SHA1 at https://crypto.stackexchange.com/questions/26510/why-is-hmac-sha1-still-considered-secure
// and at https://eprint.iacr.org/2006/187.pdf, etc. but please note that RFC 6238 "[...] is based on the HMAC-SHA-1 algorithm
// (as specified in [RFC2104])" as well as many apps like Microsoft Authenticatior, Google Authenticator and Authy
// still work only with SHA1, arguably because the collision vulnerabilities of SHA1 are barely exploitable in TOTP
// generation context where only a small portion of the hash string is used and the rest is truncated.
//
// The public methods necessary to perform the
// generation and validation actions are attached
// to this class
type TotpManager struct {
	Issuer      string
	AccountName string
	Algorithm   string
	Period      uint
	Secret      []byte // Note: use a different secret for every client/user
}

// Key creates a github.com/pquerna/otp *Key object
// which is subsequently used for creation and validation
// TOTPs
func (tm TotpManager) Key() (*otp.Key, error) {
	return genKey(tm.Issuer, tm.AccountName, tm.Period, tm.Algorithm, tm.Secret)
}

// QrCode generates a base64 encoded QR code from
// a particular TotpManager instance
func (tm TotpManager) QrCode() (string, error) {
	key, err := tm.Key()
	if err != nil {
		return "", fmt.Errorf("TotpQrCodeString failed with error [%w]", err)
	}
	qr_code_string, err := genQrCodeString(key)
	if err != nil {
		return "", fmt.Errorf("TotpQrCodeString failed with error [%w]", err)
	}
	return qr_code_string, nil
}

// TOTP creates a 6-digit time based one time
// password using on the configuration data of
// a TotpManager instance
func (tm TotpManager) TOTP() (string, error) {
	key, err := tm.Key()
	if err != nil {
		return "", fmt.Errorf("TotpMananger.TOTP failed with error [%w]", err)
	}
	return genTotp([]byte(key.Secret()), tm.Period, tm.Algorithm)
}

func (tm TotpManager) Validate(totpPasscode string) (bool, error) {
	key, err := tm.Key()
	if err != nil {
		return false, fmt.Errorf("TotpMananger.Validate failed with error [%w]", err)
	}
	selectedAlgorithm, err := algorithmSwitch(tm.Algorithm)
	if err != nil {
		return false, fmt.Errorf("TotpMananger.Validate failed with error [%w]", err)
	}
	options := totp.ValidateOpts{
		Period:    uint(key.Period()),
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: selectedAlgorithm,
	}
	return totp.ValidateCustom(totpPasscode, key.Secret(), time.Now().UTC(), options)
}

// algorithmSwitch renders a string reference to
// a hashing algorithm (e.g. "SHA1", "Sha1", "sha1", etc.) to
// its corresponding constant value in githib.com/pquerna/otp.Algorithm
func algorithmSwitch(algorithm string) (otp.Algorithm, error) {
	switch strings.ToLower(algorithm) {
	case "sha1":
		return otp.AlgorithmSHA1, nil
	case "sha256":
		return otp.AlgorithmSHA256, nil
	case "sha512":
		return otp.AlgorithmSHA512, nil
	}
	return 0, fmt.Errorf("unsupported algorithm [%v]", algorithm)
}

// genKey creates an github.com/pquerna/otp *Key instance
func genKey(issuer string, accountName string, period uint, algorithm string, secret []byte) (*otp.Key, error) {
	selectedAlgorithm, err := algorithmSwitch(algorithm)
	if err != nil {
		return nil, fmt.Errorf("genKey failed with error [%w]", err)
	}
	if period < 1 {
		return nil, fmt.Errorf("genKey failed: proposed totp period of [%v] is too short", period)
	}
	if len(secret) < 64 {
		return nil, fmt.Errorf("genKey failed: proposed secret of length [%v] is too short, min length is 64 bytes", len(secret))
	}

	options := totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Secret:      secret,
		Period:      period,
		Digits:      otp.DigitsSix,
		Algorithm:   selectedAlgorithm,
	}
	key, err := totp.Generate(options)
	if err != nil {
		return nil, fmt.Errorf("genKey failed with error [%w]", err)
	}
	return key, nil
}

// genQrCodeString generates a base64 encoded QR code
// from an github.com/pquerna/otp *Key
func genQrCodeString(key *otp.Key) (string, error) {
	var buf bytes.Buffer
	image, err := key.Image(255, 255)
	if err != nil {
		return "", fmt.Errorf("genQrCodeString failed with error [%w]", err)
	}
	if err := png.Encode(&buf, image); err != nil {
		return "", fmt.Errorf("genQrCodeString failed with error [%w]", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// genTotp generates a 6-digit TOTP
func genTotp(secret []byte, period uint, algorithm string) (string, error) {
	selectedAlgorithm, err := algorithmSwitch(algorithm)
	if err != nil {
		return "", fmt.Errorf("genTotp failed with error [%w]", err)
	}

	options := totp.ValidateOpts{
		Period:    period,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: selectedAlgorithm,
	}
	oneTimePassword, err := totp.GenerateCodeCustom(string(secret), time.Now().UTC(), options)
	if err != nil {
		return "", fmt.Errorf("genTotp failed with error [%w]", err)
	}
	return oneTimePassword, nil
}
