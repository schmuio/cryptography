# &#128273; <strong> cryptography </strong>
A developer-oriented Go library with commonly needed cryptographic operations.
<br>

### <strong> Overview </strong>  
The science of cryptography is exceedingly complex and often vulnerabilities come not from the algorithms per se but rather from subtle yet critical flaws in their implementation. We are not trying to step in the shoes of cryptographers, but to offer a compilation of trustworthy lower level implementations wrapped as developer-friendly higher level API that is safe, has everything in one place and is easy to get up and running.
<br>


### <strong> Motivation </strong>
In our experience working on enterprise software we have repeatedly encountered a gap between the need for developers to perform high level cryptographic operations and the supply of safe and in the meantime easy to use cryptoraphic recipes. Yes, all of it is out there, but getting the entire picture can take weeks, months or years depending on one's inidividual experience. We went through this journey and now want to share our work. We continue to use this library for our present and future proprietory projects.
<br>

### <strong> What's in the box </strong>
We have tried to offer most of the presently considerd industry standard cryptographic algorithms. This includes symmetric encryption, asymmetric encryption, digital signatures, time based one time passwords and multiple utility functions for managing cryptographic keys. This includes both Go native constructs based on the standard library as well as cloud-specific implementations that offer excellent security and key management features. We intend to keep updating the library with additional algorithms and welcome recommendations or feature requests.
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
We have prioritised developer convenience and ability to inspect inputs and outputs visually so most functions are designed to consume string inputs and to provide string outputs. This means that every now and then there are a few type conversions that in a _be-as-fast-as-possible_ scenario can be avoided. This does not mean the functions are not fast, on the contrary - this overhead has a infinitesimal impact compared to the computational cost of the underlying cryptographic computation. Unless you plan to apply these functions in loops with a very high number of iterations or are in a the _fastest-takes-it-all_ situations the performance is more than fine. In other words, if you need to measure performance in milliseconds or hundreds of nanoseconds - you are fine. If a few nanoseconds per operation are an issue - we recommend that you go for lower level implementations.

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

<i>Note</i>: both algoritms use [nonces](https://csrc.nist.gov/glossary/term/nonce)  (numbers-only-used-once) during encryption and reuse of such nonces can have catastrophic consequences (see _Wong, D.(2021).Real-World Cryptography.Manning Publications_ for details). In brief, do not use one key for more than 2^32 encryption operations, i.e. rotate the key as frequently as needed so this threshold is not exceeded (see _https://soatok.blog/2020/12/24/cryptographic-wear-out-for-symmetric-encryption/_ for an excellent explanation of the problem).

<br>
<strong> Example 2: Asymmetric Encryption </strong>
<br>
