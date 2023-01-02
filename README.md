# &#128273; cryptography
Application-developer-oriented library with commonly applied cryptographic operations.
<br>
<br>

## Contents 

- [Overview](#overview)
- [Motivation](#motivation)
- [What's in the box](#motivation)
- [Getting Started](#getting-started)
- [Performance](#performance)
- [Examples](#examples)
  - [Symmetric Encryption](#example-1---symmetric-encryption)
    - [AES-GCM](#example-aes-gcm)
    - [ChaCha20-Poly1305](#example-chacha20-poly1305)
  - [Asymmetric Encryption](#example-2---asymmetric-encryption)
  - [Digital Signatures](#example-3---digital-signatures)
    - [RSA-PSS](#example-rsa-pss)
    - [ECDSA-P256](#example-ecdsa-p256)
  - [Time Based One Time Passwords](#example-4---time-based-one-time-passwords)
- [Supported Algorithms](#supported-algorithms)
- [Tests](#tests)
- [Contributing](#contributing)
- [References](#references)

<br>

## Overview
A compilation of reliable lower level implementations wrapped as developer-friendly higher level API that is safe, has everything in one place and is easy to use. 
<br>
<br>

## Motivation
In our experience with enterprise software we have repeatedly encountered a gap between the the developers' need to apply cryptographic operations and the supply of safe and in the meantime easy to use cryptoraphic recipes. Yes, all of it is out there, but getting the entire picture together can take weeks, months or years depending on one's inidividual experience. We went through this journey and now would like to share our work. We intend to continue using this library for our present and future proprietary projects.
<br>
<br>

## What's in the box
We have tried to cover a meaningful variety of cryptographic algorithms which are presently considered industry standard. There are functions for symmetric encryption, asymmetric encryption, digital signatures, time based one time passwords and multiple utilities for management of cryptographic keys. One can find both Go native constructs based on the standard crypto library as well as cloud-specific implementations that offer excellent security and key management features. We intend to keep updating the library with additional algorithms and welcome recommendations or feature requests.
<br>
<br>

## Getting started
Installation:
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
<br>

## Performance
We have prioritised developer convenience and ability to inspect inputs and outputs visually so most functions are designed to consume string inputs and to provide string outputs. This means that every now and then there are a few type conversions that in a _be-as-fast-as-possible_ scenario can be avoided. This does not mean the functions are not fast, on the contrary - this overhead has a infinitesimal impact compared to the computational cost of the underlying cryptographic operation. Unless you plan to apply these functions in loops with a very high number of iterations or are in a _the-fastest-takes-it-all_ situation, the performance is more than fine. In other words, if you need to measure performance in milliseconds or hundreds of nanoseconds - you are fine. If a few nanoseconds per operation are an issue - we recommend that you go for lower level implementations.
<br>
<br>

## Examples
For the sake of avoiding repetition we assume that in every example snippet one has already imported the module via adding the following to their code:
```sh
package yourpackage

import (
    "github.com/schmuio/cryptography"
)
```

#### Example 1 - Symmetric Encryption
Symmetric encryption algorithms use the same key to encrypt the plaintext and decrypt the respective ciphertext. The library offers the two most widely used algorithms for authenticated symmetric encryption - <strong>AES-GCM</strong> and <strong>ChaCha20-Poly1305</strong> [ [1](https://www.manning.com/books/real-world-cryptography) ].
<br>

###### Example AES-GCM

Create a key:
```sh
yourKey, err := cryptography.Key256b()  // Note: alternatively Key128b() can be used
```

Encrypt:

```sh
ciphertext, err := cryptography.EncryptAesGcm("some-important-plaintext", yourKey)
```

Decrypt:
```sh
plaintext, err := cryptography.DecryptAesGcm(ciphertext, yourKey)
```

###### Example ChaCha20-Poly1305

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

&#x26A0; Both algoritms use [nonces](https://csrc.nist.gov/glossary/term/nonce)  (numbers-only-used-once) during encryption and reuse of such nonces can have catastrophic consequences (see [ [1](https://www.manning.com/books/real-world-cryptography) ] for details). In brief, do not use one key for more than 2^32 encryption operations, i.e. rotate the key as frequently as needed so this threshold is not exceeded (see [ [7](https://soatok.blog/2020/12/24/cryptographic-wear-out-for-symmetric-encryption/) ] for an excellent explanation of the problem).
<br>

#### Example 2 - Asymmetric Encryption

Asymmetric encryption algorithms use one key (referred to as 'public key') to encrypt data and another one (referred to as 'private key') to decrypt them. This is particularly useful in scenarios where many parties should be able to encrypt certain information but there is only one party that is to be allowed to decrypt it. Make sure the private key is <i> always </i> stored securely and do not share it. You can share the public key freely and do not need to treat it as a secret. The library implements the ubiquitous <strong>RSA-OAEP</strong> algorithm for asymmetric encryption/decryption.
<br>
<br>
Create a key:

```sh
privateKey, publicKey, err := cryptography.RsaKeyPairPem()
```

Encrypt:

```sh
ciphertext, err := cryptography.EncryptRsa("some-important-plaintext", publicKey)
```

Decrypt:

```sh
plaintext, err := cryptography.DecryptRsa(ciphertext, privateKey)
```
 
&#x26A0; RSA encryption is not designed to encrypt large messages and the maximim size of the plaintext is restricted by the size of the public key (e.g. 2048 bits) including deductions for padding, etc., details can be found in [ [5](https://mbed-tls.readthedocs.io/en/latest/kb/cryptography/rsa-encryption-maximum-data-size/) ]. If you need to encrypt longer messages and still rely on an asymmetric encryption workflow a solution is to use hybrid encryption - use a symmetric algorithm for the data and encrypt the symmetric key with an asymmetric algorithm.
<br>

#### Example 3 - Digital signatures
Digital signatures are asymmetric cryptography entities that provide proof of the orgin of a message and its integrity (i.e. that it comes from the expected source and that it has not been modified). Digital signatures are issued with the private key and are verified with the public key. The private key should be stored securely at all times and should never be shared. The puplic key can be shared with any party that is interested in checking messages signed by the issuer who holds the private key. 

###### Example RSA PSS

Create a key:

```sh
privateKey, publicKey, err := cryptography.RsaKeyPairPem()
```

Sign:
```sh
signature, err := cryptography.SignRsaPss("some-very-important-message", privateKeyPem)
```
Veryfy signature
```sh
err = cryptography.VerifyRsaPss("some-very-important-message", signature, publicKeyPem)
```

###### Example ECDSA P256

```sh
privateKey, publicKey, err := cryptography.EcdsaKeyPairHex()
```

Sign:
```sh
signature, err := cryptography.SignEcdsa("some-very-important-message", privateKey)
```
Veryfy signature
```sh
err = cryptography.VerifyEcdsa("some-very-important-message", signature, publicKey)
```

&#x26A0; It is recomended that RSA-PSS or ECDSA is used whenever possible whereas RSA-PKCS1v15 is also included for cases where compatibility mandades the use of the latter. See [ <a href="https://www.manning.com/books/real-world-cryptography">1</a> ] for a detailed review and comparison of digital signatures algorithms.
<br>


#### Example 4 - Time based one-time passwords
 
TOTPs are a highly popular method for adding extra security, e.g. in multi-factor authentication settings. They are derived from the present Unix time and a shared secret provided to an HMAC algorithm. The synchronisation of the Unix time clocks of the client and the server, as well as their shared secret, combined with a deterministic hash algorithm enusure that both parties can derive the same code independently, see details here <a href="https://www.ietf.org/rfc/rfc6238.txt">RFC6238</a>. The library provides a straightforward-to-use API for creating TOTPs and secrets rendered as QR codes so that one can very easily integrate it with 2FA apps like Authy, Google Authenticator, Microsoft Authenticator, etc.
<br>
<br>

Initial step: create a TotpManager instance with all the necessary data:

```sh
 secret, err := cryptography.Key512b() // Note: the secret must be of 64-byte size
 if err != nil {
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
if err != nil {
    // error handling logic
}
```

Validate a TOTP:
```sh
isValid, err := tm.Validate(totp)
if err != nil {
    // error handling logic
}
```

Generate QR code:
```sh
qrCodeBase64, err := tm.QrCode()
if err != nil {
    // error handling logic
}

// Render this QR code (bs64 encoded image) on your UI to allow the user to onboard for 2-factor authentication with an app like Authy, Google Authenticatior, etc.
```

<br>
&#x26A0; TOTPs standardised with <a href="https://www.ietf.org/rfc/rfc6238.txt">RFC6238</a> use SHA1 as an HMAC algorithm and the latter is still in seemingly wide use in TOTP contexts. At the time of writing (Decemeber, 2022) <a href="https://authy.com/">Authy</a>, <a href="https://googleauthenticator.net/">Google Authenticator</a> and <a href="https://www.microsoft.com/en-us/security/mobile-authenticator-app">Microsoft Authenticator</a> still default to SHA1 and when TOTPs created with SHA256 or SHA512 are passed the latter apps still expect the SHA1-based value. On the other hand others like <a href="https://www.ibm.com/docs/en/sva/9.0.2.1?topic=verify-application">IBM Verify</a> and <a href="https://docs.sophos.com/esg/smsec/help/en-us/esg/Sophos-Mobile-Security/concepts/Authenticator.html">Sophos Authenticator</a> seem to already be supporting SHA256-based TOTPs.
<br>
<br>
The problem is that for long time SHA1 has been proven to be fundamentally insecure and is no longer recommended by NIST [<a href="[https://duo.com/decipher/sha-1-fully-and-practically-broken-by-new-collision](https://nostarch.com/seriouscrypto)" target="_blank"> 2 </a>], and evidence has been growing it is even more flawed with respect to collision resistance than previously thought [<a href="https://duo.com/decipher/sha-1-fully-and-practically-broken-by-new-collision" target="_blank"> 3 </a>], [<a href="https://eprint.iacr.org/2020/014.pdf" target="_blank"> 4 </a>]. However, reportedly it has been "relatively safe" in other contexts [<a href="https://eprint.iacr.org/2020/014.pdf" target="_blank"> 4 </a>]. For example, in TOTP generation collision resitance is not a required property as well as only a small 6-digit part of the whole hash is used so that the generic collision attacks do not seem to be particularlly applicable.
<br>
<br>
For our purposes we prefer to use SHA256, however we do not argue that the SHA1 cannot be safely used in such a context.

<br>
<br>

## Supported Algorithms

- AES-GCM | symmetric encryption | native*

- AES-GCM | symmetric encryption | via Google Cloud Platform

- ChaCha20-Poly1305 | symmetric encryption | native

- RSA-OAEP | asymmetric encryption | native

- RSA-OAEP | asymmetric encryption | via Google Cloud Platform

- RSA-PKCS1v15 | digital signatures | native

- RSA-PKCS1v15 | digital signatures | via Google Cloud Platform

- RSA-PSS | digital signatures | native

- RSA-PSS | digital signatures | via Google Cloud Platform

- ECDSA p256 | digital signatures | native

- ECDSA p256/p384/secp256k1 | digital signatures | via Google Cloud Platform

- RFC 6238 | time-based one-time passwords | native
<br>

*<i>native</i> refers to as locally executable code which does not rely on any external infrastructure
<br>
<br>
 
## Tests
Best effort has been made the code to be covered with meaningful tests. In order the Google Cloud Platform KMS-based encryption tests (and functions) to work, one needs to create keys as described in the GCP [documentation](https://cloud.google.com/kms/docs/algorithms) - for symmetric encrypt/decrypt, asymmetric encrypt/decrypt and asymmetric sign/verify purposes and set their resource names to the environment variables:
- TEST_GKMS_SYMMETRIC_ENCRYPTION_KEY_RESOURCE_NAME
- TEST_GKMS_RSA_ENCRYPTION_PRIVATE_KEY_RESOURCE_NAME
- TEST_GKMS_RSA_SIGN_PRIVATE_KEY_RESOURCE_NAME
- TEST_GKMS_RSA_SIGN_PUBLIC_KEY_PEM.
<br>
If you intend to use only the native encryption functions please set DISABLE_GCP_TESTS to "1".
<br>
<br>

## Contributing

At present we plan to maintain this library on our own because it is getting shaped by the needs of the projects we are and will be applying it for. As time is particularly limited, we prefer to not manage this repo as a particularly dynamic one. Nevertheless, we would warmly welcome any remarks, recommendations, feature requests or contribution proposals which we'll review on an individual basis. We commit to fix any bugs and inconsistencies in due course. Please contact us on schmu.io@proton.me on any matter of interest.  
<br>
 

## References

[1] Wong, D.(2021).<i>Real-World Cryptography</i>.Manning Publications
<br>
<br>
[2] Aumasson, J.P.(2017).<i>Serious Cryptography</i>.No Starch Press
<br>
<br>
[3] https://duo.com/decipher/sha-1-fully-and-practically-broken-by-new-collision
<br>
<br>
[4] https://eprint.iacr.org/2020/014.pdf
<br>
<br>
[5] https://mbed-tls.readthedocs.io/en/latest/kb/cryptography/rsa-encryption-maximum-data-size/)
<br>
<br>
[6] https://csrc.nist.gov/glossary/term/nonce
<br>
<br>
[7] https://soatok.blog/2020/12/24/cryptographic-wear-out-for-symmetric-encryption/
<br>
<br>
[8] https://www.ietf.org/rfc/rfc6238.txt
