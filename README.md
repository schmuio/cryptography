# &#128273; cryptography
A developer-oriented Go library with commonly needed cryptographic operations.

<br>

### <strong> Overview </strong>  
The science of cryptography is <i>hugely</i> complex and often the worst vulnerabilities come not from the algorithms per se but rather from slight but critical flaws in their implementation. We are not trying to step in the shoes of cryptographers, but to offer a compilation of trustworthy lower level implementations wrapped as developer-friendly higher level API that is safe, has everything in one place and is very easy to get up and running.
<br><br>
### <strong> Motivation </strong>
In our experience working on enterprise software we have repeatedly encountered a gap between the need for developers to perform high level cryptographic operations and the supply of safe and in the meantime easy to use cryptoraphic recipes. Yes, all of it is out there, but getting the entire picture can take weeks, months or years depending on one's inidividual experience with cryptography. We went through this journey developing various enterprise solutions and now want to share our work. We continue to use this library for our present and future proprietory projects.
<br><br>
### <strong> What's in the box </strong>
We have tried to offer most of the presently considerd industry standard cryptographic algorithms. This includes symmetric encryption, asymmetric encryption, digital signatures, time based one time passwords and multiple utility functions for managing cryptographic keys. This inclides both Go native constructs based on the standard library as well as We intend to keep updating the library with additional algorithms and welcome and recommendations or feature requests.
<br><br>
### <strong> Getting started </strong>
Intall the library
```sh
go get -u github.com/gin-gonic/gin
```
Import it in your code
```sh
package yourpackage

import (
    "github.com/schmuio/cryptography"
)
yourKey, err := cryptography.Key256b()
if err != nil {
    // Do something about it
}
ciphertext, err := cryptography.EncryptAes("some-important-plaintext", yourKey)
...
```


