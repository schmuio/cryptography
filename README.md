# &#128273; <strong> cryptography </strong>
A developer-oriented Go library with commonly applied cryptographic operations.
<br>

### <strong> Overview </strong>
A compilation of trustworthy lower level implementations wrapped as developer-friendly higher level API that is safe, has everything in one place and is easy to get up and running. 
<br>

### <strong> Motivation </strong>
In our experience working on enterprise software we have repeatedly encountered a gap between the need for developers to perform high level cryptographic operations and the supply of safe and in the meantime easy to use cryptoraphic recipes. Yes, all of it is out there, but getting the entire picture can take weeks, months or years depending on one's inidividual experience. We went through this journey and now would like to share our work. We will continue to use this library for our present and future proprietary projects.
<br>

### <strong> What's in the box </strong>
We have tried to cover a meaningful variety of cryptographic algorithms which are presently considered industry standard. There are functions for symmetric encryption, asymmetric encryption, digital signatures, time based one time passwords and multiple utilities for management of cryptographic keys. One can find both Go native constructs based on the standard crypto library as well as cloud-specific implementations that offer excellent security and key management features. We intend to keep updating the library with additional algorithms and welcome recommendations or feature requests.
<br>


### <strong> Getting started </strong>
Install the library:
```sh
go get github.com/schmuio/cryptography
```
Import it in your code and and you are ready to go:
```sh
package yourpackage

import (
    "github.com/schmuio/cryptography"
)
yourKey, err := cryptography.Key256b()
if err != nil {
    // error handling logic
}
ciphertext, err := cryptography.EncryptAesGcm("some-important-plaintext", yourKey)
```

### <strong> Performance and convenience </strong>
We have prioritised developer convenience and ability to inspect inputs and outputs visually so most functions are designed to consume string inputs and to provide string outputs. This means that every now and then there are a few type conversions that in a _be-as-fast-as-possible_ scenario can be avoided. This does not mean the functions are not fast, on the contrary - this overhead has a infinitesimal impact compared to the computational cost of the underlying cryptographic operation. Unless you plan to apply these functions in loops with a very high number of iterations or are in a the _fastest-takes-it-all_ situations the performance is more than fine. In other words, if you need to measure performance in milliseconds or hundreds of nanoseconds - you are fine. If a few nanoseconds per operation are an issue - we recommend that you go for lower level implementations.

### <strong> Examples </strong>
For the sake of avoiding repetition we assume that in every example snippet one has already imported the module via adding the following to the code:
```sh
package yourpackage

import (
    "github.com/schmuio/cryptography"
)
```
<br>
<strong> Example 1: Symmetric Encryption </strong>
<br>
Symmetric encryption algorithms use the same key to encrypt the plaintext and decrypt the respective ciphertext. The library offers the two most widely used algorithms for authenticated symmetric encryption - <strong>AES-GCM</strong> and <strong>ChaCha20-Poly1305</strong>.
<br><br>

<i>In case of the AES-GCM algorithm:</i> <br><br>
Create a key:
```sh
yourKey, err := cryptography.Key256b()  // Note: alternatively Key128b() or Key512b() can be used
```

Encrypt:

```sh
ciphertext, err := cryptography.EncryptAesGcm("some-important-plaintext", yourKey)
```

Decrypt:
```sh
plaintext, err := cryptography.DecryptAesGcm(ciphertext, yourKey)
```

<br>
<i>In case of the ChaCha20-Poly1305 algorithm:</i> <br><br>
Create a key:

```sh
yourKey, err := cryptography.KeyChaCha20()
```

Encrypt:

```sh
ciphertext, err := cryptography.EncryptChaCha20("some-important-plaintext", yourKey)
```

Decrypt:

```sh
plaintext, err := cryptography.DecryptChaCha20(ciphertext, yourKey)
```
<br>

<i>Note</i>: both algoritms use [nonces](https://csrc.nist.gov/glossary/term/nonce)  (numbers-only-used-once) during encryption and reuse of such nonces can have catastrophic consequences (see _Wong, D.(2021).Real-World Cryptography.Manning Publications_ for details). In brief, do not use one key for more than 2^32 encryption operations, i.e. rotate the key as frequently as needed so this threshold is not exceeded (see this [post](https://soatok.blog/2020/12/24/cryptographic-wear-out-for-symmetric-encryption/) for an excellent explanation of the problem).

<br>
<strong> Example 2: Asymmetric Encryption </strong>
Asymmetric encryption algorithms use one key (referred to as 'public key') to encrypt data and another one (referred to as 'private key') to decrypt them. This is particularly useful in scenarios where many parties should be able to encrypt certain information but there is only one party that is to be allowed to decrypt it. Make sure the private key is <i> always </i> stored securely and do not share it. You can share the public key freely and do not need to treat it as a secret. The library implements the ubiquitous <strong>RSA-OAEP</strong> algorithm for asymmetric encryption/decryption.
<br>
<br>
Create a key:

```sh
privateKey, publicKey err := cryptography.RsaKeyPairPem()
```

Encrypt:

```sh
ciphertext, err := cryptography.EncryptRsa("some-important-plaintext", publicKey)
```

Decrypt:

```sh
plaintext, err := cryptography.DecryptRsa(ciphertext, privateKey)
```
 
 <i>Note</i>: RSA encryption is not designed to encrypt large messages and the maximim size of the plaintext is restricted by the size of the public key (e.g. 2048 bits) including deductions for padding, etc., details can be found [here](https://mbed-tls.readthedocs.io/en/latest/kb/cryptography/rsa-encryption-maximum-data-size/). If you need to encrypt longer messages and still rely on an asymmetric encryption workflow a solution is to use hybrid encryption - use a symmetric algorithm for the data and encrypt the symmetric key with an asymmetric algorithm.
 

<br>
<strong> Example 3: Time based one-time passwords </strong>
<br>
TOTPs are highly prevalent method for adding extra security, e.g. in multi-factor authentication settings. They are derived from the present Unix time and a shared secret provided to an HMAC algorithm. The synchronisation of the Unix time clocks of the client and the server, as well as their shared secret, combined with a deterministic hash algorithm enusure that both parties get the same code independently, see details <a href="https://www.ietf.org/rfc/rfc6238.txt">here</a>. The library provides a straightforward-to-use API for creating TOTPs and secrets rendered as QR codes so that one can very easily integrate it with 2FA apps like Authy, Google Authenticator, Microsoft Authenticator, etc.
<br>

Initial step: create a TotpManager instance with all the necessary data:

```sh
 secret, err := cryptography.Key512b() // Note: the secret must be of this size
 if err := nil {
    // error handling logic
 }

 tm := cryptography.TotpManager{
		Issuer:      "yourOrganization",
		AccountName: "yourUserEmail@yourOrganization.com",
		Algorithm:   "SHA1",         // Or SHA256, SHA512
		Period:      30,             // The default period is 30s
		Secret:      []byte(secret), // Use different secret per every client
	}
```

Generate a TOTP:
```sh
totp, err := tm.TOTP()  // The result is a string of 6 decimal digits like "123456"
if err := nil {
    // error handling logic
}
```

Validate a TOTP:
```sh
isValid, err := tm.Validate(totp)
if err := nil {
    // error handling logic
}
```

Generate QR code:
```sh
qrCodeBase64, err := tm.QrCode()
if err := nil {
    // error handling logic
}

// Render this QR code (bs64 encoded image) on your UI to allow the user to onboard for 2-factor authentication with an app like Authy, Google Authenticatior, etc.
```
