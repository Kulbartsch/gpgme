# GPGME (golang)

Go wrapper for the [GPGME library](https://www.gnupg.org/related_software/gpgme/).

This is a fork from [github.com/proglottis/gpgme](https://github.com/proglottis/gpgme).

This fork implements some more GPGME functions.


## Installation

    go get -u github.com/kulbartsch/gpgme

### Build with GPGME V2 support

GPGME V2 supports the use of GnuPGs secure and certified random number
generator.

To build with GPGME V2 support, use the following command:

    go build -tags gpgme2


## Documentation

* [godoc](https://pkg.go.dev/github.com/kulbartsch/gpgme)
* [GnuPG GPGME manual](https://www.gnupg.org/documentation/manuals.html)

## Alternative

* [golang.org/x/crypto/openpgp](https://godoc.org/golang.org/x/crypto/openpgp) - deprecated
* [github.com/ProtonMail/go-crypto/openpgp](https://github.com/ProtonMail/go-crypto) - active fork of the previous
