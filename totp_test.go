package cryptography

import (
	"encoding/base32"
	"fmt"
	"github.com/pquerna/otp"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

var testSecret []byte = []byte("a75dd8638ccf8c13c53ae5ecbb76ca74f717254eb700b852f1b00e575c9ba43a")

func Test_algorithmSwitch_SHA1(t *testing.T) {
	// Want: upon different string references to the algorithm name, the right opt.Algorithm representation is selected
	for _, algo := range []string{"SHA1", "Sha1", "SHa1", "sHA1", "sha1"} {
		selection, err := algorithmSwitch(algo)
		if err != nil {
			t.Errorf(err.Error())
			break
		}
		assert.Equal(t, otp.AlgorithmSHA1, selection)
	}
}

func Test_algorithmSwitch_SHA256(t *testing.T) {
	// Want: upon different string references to the algorithm name, the right opt.Algorithm representation is selected
	for _, algo := range []string{"SHA256", "Sha256", "SHa256", "sHA256", "sha256"} {
		selection, err := algorithmSwitch(algo)
		if err != nil {
			t.Errorf(err.Error())
			break
		}
		assert.Equal(t, otp.AlgorithmSHA256, selection)
	}
}

func Test_algorithmSwitch_SHA512(t *testing.T) {
	// Want: upon different string references to the algorithm name, the right opt.Algorithm representation is selected
	for _, algo := range []string{"SHA512", "Sha512", "SHa512", "sHA512", "sha512"} {
		selection, err := algorithmSwitch(algo)
		if err != nil {
			t.Errorf(err.Error())
			break
		}
		assert.Equal(t, otp.AlgorithmSHA512, selection)
	}
}

func Test_algorithmSwitch_invalidAlgorithm(t *testing.T) {
	// Want: return an error with the right content upon an invalid/unsupported hash algorithm
	var err error
	for _, algo := range []string{"", "no-such-algorithm", "MD5"} {
		_, err = algorithmSwitch(algo)
		if err == nil {
			t.Errorf("should have raised an error on unsupported hash algorithm")
		}
		assert.Equal(t, fmt.Sprintf("unsupported algorithm [%v]", algo), err.Error())
	}
}

func Test_genKey_Basic(t *testing.T) {
	// Want: an *otp.Key with the correct parameters is created
	testIssuer := "TestIssuer"
	testAccountName := "testAccountName@company.com"
	algorithm := "Sha1"
	var period uint = 60
	key, err := genKey(testIssuer, testAccountName, period, algorithm, testSecret)
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Equal(t, testIssuer, key.Issuer())
	assert.Equal(t, testAccountName, key.AccountName())
	assert.Equal(t, int(key.Period()), int(period))
	assert.Equal(t, strings.Contains(strings.ToLower(key.URL()), strings.ToLower(algorithm)), true)
	b32NoPadding := base32.StdEncoding.WithPadding(base32.NoPadding)
	secret, err := b32NoPadding.DecodeString(key.Secret())
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Equal(t, 64, len(secret))
}

func Test_TotpManager_Key_Basic(t *testing.T) {
	// Want: an *otp.Key with the correct parameters is created
	testIssuer := "TestIssuer"
	testAccountName := "testAccountName@company.com"
	algorithm := "Sha1"
	var period uint = 60
	tMngr := TotpManager{
		Issuer:      testIssuer,
		AccountName: testAccountName,
		Algorithm:   algorithm,
		Period:      period,
		Secret:      testSecret,
	}
	key, err := tMngr.Key()
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Equal(t, testIssuer, key.Issuer())
	assert.Equal(t, testAccountName, key.AccountName())
	assert.Equal(t, int(key.Period()), int(period))
	assert.Equal(t, strings.Contains(strings.ToLower(key.URL()), strings.ToLower(algorithm)), true)
	b32NoPadding := base32.StdEncoding.WithPadding(base32.NoPadding)
	secret, err := b32NoPadding.DecodeString(key.Secret())
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Equal(t, 64, len(secret))
}

func Test_genKey_OnAllAgorithms(t *testing.T) {
	// Want: keys to be created successfully on all supported algorithms
	for _, algorithm := range []string{"SHA1", "Sha1", "SHa1", "sHA1", "sha1", "SHA256", "Sha256", "SHa256", "sHA256", "sha256", "SHA512", "Sha512", "SHa512", "sHA512", "sha512"} {
		testIssuer := "TestIssuer"
		testAccountName := "testAccountName@company.com"
		var period uint = 60
		key, err := genKey(testIssuer, testAccountName, period, algorithm, testSecret)
		if err != nil {
			t.Errorf(err.Error())
			break
		}
		assert.Equal(t, strings.Contains(strings.ToLower(key.URL()), strings.ToLower(algorithm)), true)
	}
}

func Test_TotpManager_Key_OnAllAgorithms(t *testing.T) {
	// Want: keys to be created successfully on all supported algorithms
	for _, algorithm := range []string{"SHA1", "Sha1", "SHa1", "sHA1", "sha1", "SHA256", "Sha256", "SHa256", "sHA256", "sha256", "SHA512", "Sha512", "SHa512", "sHA512", "sha512"} {
		testIssuer := "TestIssuer"
		testAccountName := "testAccountName@company.com"
		var period uint = 60
		tMngr := TotpManager{
			Issuer:      testIssuer,
			AccountName: testAccountName,
			Algorithm:   algorithm,
			Period:      period,
			Secret:      testSecret,
		}
		key, err := tMngr.Key()
		if err != nil {
			t.Errorf(err.Error())
			break
		}
		assert.Equal(t, strings.Contains(strings.ToLower(key.URL()), strings.ToLower(algorithm)), true)
	}
}

func Test_genKey_onInvalidInputs(t *testing.T) {
	// Want: the correct error is returned on a missing issuer
	key, err := genKey("", "some-account-id", 60, "Sha1", testSecret)
	if key != nil {
		t.Errorf("should have not created a key on invalid inputs")
	}
	assert.Equal(t, "genKey failed with error [Issuer must be set]", err.Error())

	// Want: the correct error is returned on a missing account name
	key, err = genKey("some-issuer-id", "", 60, "Sha1", testSecret)
	if key != nil {
		t.Errorf("should have not created a key on invalid inputs")
	}
	assert.Equal(t, "genKey failed with error [AccountName must be set]", err.Error())

	// Want: the correct error is returned on an invalid period
	key, err = genKey("some-issuer-id", "some-account-id", 0, "Sha1", testSecret)
	if key != nil {
		t.Errorf("should have not created a key on invalid inputs")
	}
	assert.Equal(t, "genKey failed: proposed totp period of [0] is too short", err.Error())

	// Want: the correct error is returned on invalid algorithm
	key, err = genKey("some-issuer-id", "some-account-id", 60, "no-such-algorithm", testSecret)
	if key != nil {
		t.Errorf("should have not created a key on invalid inputs")
	}
	assert.Equal(t, "genKey failed with error [unsupported algorithm [no-such-algorithm]]", err.Error())

	// Want: the correct error is returned on too short a secret
	key, err = genKey("some-issuer-id", "some-account-id", 60, "Sha1", []byte("too-short-a-secret"))
	if key != nil {
		t.Errorf("should have not created a key on invalid inputs")
	}
	assert.Equal(t, "genKey failed: proposed secret of length [18] is too short, min length is 64 bytes", err.Error())
}

func Test_TotpManager_Key_onInvalidInputs(t *testing.T) {
	// Want: the correct error is returned on a missing issuer
	tMngr := TotpManager{
		Issuer:      "",
		AccountName: "some-account-id",
		Algorithm:   "Sha1",
		Period:      60,
		Secret:      testSecret,
	}
	key, err := tMngr.Key()
	if key != nil {
		t.Errorf("should have not created a key on invalid inputs")
	}
	assert.Equal(t, "genKey failed with error [Issuer must be set]", err.Error())

	// Want: the correct error is returned on a missing account name
	tMngr = TotpManager{
		Issuer:      "some-issuer",
		AccountName: "",
		Algorithm:   "Sha1",
		Period:      60,
		Secret:      testSecret,
	}
	key, err = tMngr.Key()
	if key != nil {
		t.Errorf("should have not created a key on invalid inputs")
	}
	assert.Equal(t, "genKey failed with error [AccountName must be set]", err.Error())

	// Want: the correct error is returned on an invalid period
	tMngr = TotpManager{
		Issuer:      "some-issuer",
		AccountName: "some-account-id",
		Algorithm:   "Sha1",
		Period:      0,
		Secret:      testSecret,
	}
	key, err = tMngr.Key()
	if key != nil {
		t.Errorf("should have not created a key on invalid inputs")
	}
	assert.Equal(t, "genKey failed: proposed totp period of [0] is too short", err.Error())

	// Want: the correct error is returned on invalid algorithm
	tMngr = TotpManager{
		Issuer:      "some-issuer",
		AccountName: "some-account-id",
		Algorithm:   "no-such-algorithm",
		Period:      60,
		Secret:      testSecret,
	}
	key, err = tMngr.Key()
	if key != nil {
		t.Errorf("should have not created a key on invalid inputs")
	}
	assert.Equal(t, "genKey failed with error [unsupported algorithm [no-such-algorithm]]", err.Error())

	// Want: the correct error is returned on too short a secret
	tMngr = TotpManager{
		Issuer:      "some-issuer",
		AccountName: "some-account-id",
		Algorithm:   "Sha1",
		Period:      60,
		Secret:      []byte("too-short-a-secret"),
	}
	key, err = tMngr.Key()
	if key != nil {
		t.Errorf("should have not created a key on invalid inputs")
	}
	assert.Equal(t, "genKey failed: proposed secret of length [18] is too short, min length is 64 bytes", err.Error())
}

func Test_genQrCodeString(t *testing.T) {
	// Want: a valid base64 encoded QR code is created
	testIssuer := "TestIssuer"
	testAccountName := "testAccountName@company.com"
	var period uint = 60
	algorithm := "Sha1"
	tMngr := TotpManager{
		Issuer:      testIssuer,
		AccountName: testAccountName,
		Algorithm:   algorithm,
		Period:      period,
		Secret:      testSecret,
	}
	key, err := tMngr.Key()
	if err != nil {
		t.Errorf(err.Error())
	}
	qr_string, err := genQrCodeString(key)
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Greater(t, len(qr_string), 2048)
}

func Test_TotpManager_QrCode(t *testing.T) {
	// Want: a valid base64 encoded QR code is created
	testIssuer := "TestIssuer"
	testAccountName := "testAccountName@company.com"
	var period uint = 60
	algorithm := "Sha1"
	tMngr := TotpManager{
		Issuer:      testIssuer,
		AccountName: testAccountName,
		Algorithm:   algorithm,
		Period:      period,
		Secret:      testSecret,
	}
	qr_string, err := tMngr.QrCode()
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Greater(t, len(qr_string), 2048)
}

func Test_genTotp(t *testing.T) {
	// Want: a valid 6-digit TOTP is created
	var tMngr TotpManager
	var period uint = 60
	for _, algorithm := range []string{"SHA1", "Sha1", "SHa1", "sHA1", "sha1", "SHA256", "Sha256", "SHa256", "sHA256", "sha256", "SHA512", "Sha512", "SHa512", "sHA512", "sha512"} {
		tMngr = TotpManager{
			Issuer:      "some-issuer",
			AccountName: "some-account-name",
			Algorithm:   algorithm,
			Period:      period,
			Secret:      testSecret,
		}
		key, err := tMngr.Key()
		if err != nil {
			t.Errorf(err.Error())
		}

		oneTimePassword, err := genTotp([]byte(key.Secret()), period, algorithm)
		if err != nil {
			t.Errorf(err.Error())
			break
		}
		assert.Equal(t, 6, len(oneTimePassword))
	}
}

func Test_TotpManager_TOTP(t *testing.T) {
	// Want: a valid 6-digit TOTP is created
	var tMngr TotpManager
	var period uint = 60
	for _, algorithm := range []string{"SHA1", "Sha1", "SHa1", "sHA1", "sha1", "SHA256", "Sha256", "SHa256", "sHA256", "sha256", "SHA512", "Sha512", "SHa512", "sHA512", "sha512"} {
		tMngr = TotpManager{
			Issuer:      "some-issuer",
			AccountName: "some-account-name",
			Algorithm:   algorithm,
			Period:      period,
			Secret:      testSecret,
		}
		oneTimePassword, err := tMngr.TOTP()
		if err != nil {
			t.Errorf(err.Error())
			break
		}
		assert.Equal(t, 6, len(oneTimePassword))
	}
}

func Test_TotpManager_TOTP_Different_TOTPs_per_algorithm(t *testing.T) {
	// Want: different TOTPs are created with different hashing algorithms
	// Note: this is primarily to test the inderlying TOTP dependencies
	var tMngr1, tMngr2, tMngr3 TotpManager
	var period uint = 60
	tMngr1 = TotpManager{
		Issuer:      "some-issuer",
		AccountName: "some-account-name",
		Algorithm:   "Sha1",
		Period:      period,
		Secret:      testSecret,
	}
	oneTimePassword1, err := tMngr1.TOTP()
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Equal(t, 6, len(oneTimePassword1))

	tMngr2 = TotpManager{
		Issuer:      "some-issuer",
		AccountName: "some-account-name",
		Algorithm:   "Sha256",
		Period:      period,
		Secret:      testSecret,
	}
	oneTimePassword2, err := tMngr2.TOTP()
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Equal(t, 6, len(oneTimePassword2))

	tMngr3 = TotpManager{
		Issuer:      "some-issuer",
		AccountName: "some-account-name",
		Algorithm:   "Sha512",
		Period:      period,
		Secret:      testSecret,
	}
	oneTimePassword3, err := tMngr3.TOTP()
	if err != nil {
		t.Errorf(err.Error())
	}
	assert.Equal(t, 6, len(oneTimePassword3))
	assert.Equal(t, oneTimePassword1 != oneTimePassword2, true)
	assert.Equal(t, oneTimePassword2 != oneTimePassword3, true)
	assert.Equal(t, oneTimePassword1 != oneTimePassword3, true)
}

func Test_TotpManager_ValidateOnCorrectPassword(t *testing.T) {
	// Want: correct password is validated
	for _, algo := range []string{"Sha1", "Sha256", "Sha512"} {
		tMngr := TotpManager{
			Issuer:      "some-issuer",
			AccountName: "some-account-name",
			Algorithm:   algo,
			Period:      30,
			Secret:      testSecret,
		}
		oneTimePassword, err := tMngr.TOTP()
		if err != nil {
			t.Errorf(err.Error())
			break
		}
		isValid, err := tMngr.Validate(oneTimePassword)
		if err != nil {
			t.Errorf(err.Error())
			break
		}
		assert.Equal(t, true, isValid, "note: due to the nature of TOTPs rarely this test can fail stochastically")
	}
}

func Test_TotpManager_ValidateOnIncorrectPass(t *testing.T) {
	// Want: incorrect password is not validated
	for _, algo := range []string{"Sha1", "Sha256", "Sha512"} {
		tMngr := TotpManager{
			Issuer:      "some-issuer",
			AccountName: "some-account-name",
			Algorithm:   algo,
			Period:      30,
			Secret:      testSecret,
		}
		oneTimePassword := "000000"
		isValid, err := tMngr.Validate(oneTimePassword)
		if err != nil {
			t.Errorf(err.Error())
			break
		}
		assert.Equal(t, false, isValid, "rarely this test can fail stochastically")
	}
}
