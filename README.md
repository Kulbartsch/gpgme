# GPGME (golang)

Go wrapper for the [GPGME library](https://www.gnupg.org/related_software/gpgme/).

This is a fork from [github.com/proglottis/gpgme](https://github.com/proglottis/gpgme).

This fork implements more GPGME functions and code documentation.


## Installation

    go get -u github.com/kulbartsch/gpgme

### Build hints

If you have an updated *GPGME* version installed in a non-standard
location, you may need to tell the Go compiler where to find the
corrsesponding `pkgconfig` file.

For example, if GPGME is installed under `/usr/local`, you can build
your Go program using:

```bash
PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH \
go build
```

If you have trouble building the package maybe try to clean the Go
build caches:

    go clean -cache

and/or

    rm -rf ~/.cache/go-build


## Documentation

* [godoc](https://pkg.go.dev/github.com/kulbartsch/gpgme)
* [GnuPG GPGME manual](https://www.gnupg.org/documentation/manuals.html)

## Alternative

* [golang.org/x/crypto/openpgp](https://godoc.org/golang.org/x/crypto/openpgp) - deprecated
* [github.com/ProtonMail/go-crypto/openpgp](https://github.com/ProtonMail/go-crypto) - active fork of the previous

## License

This project is licensed under the BSD 3-Clause License.
See the [LICENSE](LICENSE)
