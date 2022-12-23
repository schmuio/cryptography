# &#128273; <strong> cryptography </strong>
A developer-oriented Go library with commonly needed cryptographic operations.
<br>

### <strong> Overview </strong>  
The science of cryptography is exceedingly complex and often the worst vulnerabilities come not from the algorithms per se but rather from subtle yet critical flaws in their implementation. We are not trying to step in the shoes of cryptographers, but to offer a compilation of trustworthy lower level implementations wrapped as developer-friendly higher level API that is safe, has everything in one place and is easy to get up and running.
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
Import it in your code and get going:
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

### <strong> Convenience and speed </strong>
We have prioritised developer convenience and ability to inspect inputs and outputs visually so most functions are designed to consume string inputs and to provide string outputs. This means that every now and then there are a few type conversions that in a _be-as-fast-as-possible_ scenario can be avoided. Unless you plan to apply these functions in loops with a very high number of iterations or are in a the _fastest-takes-it-all_ situations the performance is more than fine. Put otherwise, if you need to measure performance in milliseconds or hundreds of nanoseconds - you are fine. If a few nanoseconds per operation are an issue - we recommend that you go for lower level implementations.

Perhaps meticulous Go developers could notice we have had the liberty of allowing few underscores every now and then. Always respectful of convention, we have reckoned this is helping readability.

### <strong> Examples </strong>
For the sake of avoiding repetition we assume that in every example snipped one has already imported the module via adding the following to the code:
```sh
package yourpackage

import (
    "fmt"
    "otherstuff"
    "morestuff"
    "github.com/schmuio/cryptography"
)
```

