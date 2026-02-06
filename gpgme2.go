// Package gpgme provides a Go wrapper for the GPGME 2 library
package gpgme

// #cgo pkg-config: gpgme
// #cgo CPPFLAGS: -D_FILE_OFFSET_BITS=64
// #include <stdlib.h>
// #include <gpgme.h>
// #include "go_gpgme.h"
import "C"

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"
)

// -- random bytes --

// RandomBytes returns a random []byte array.
// It will return *buffer* filled with *lenght* random bytes
// retrieved from gpg. (random mode GPGME_RANDOM_MODE_NORMAL)
// The caller must provide a context ctx initialized for
// GPGME_PROTOCOL_OPENPGP. This function has a limit of 1024 bytes
// to avoid accidental overuse of the random generator.
// Since gpgme 2.0
func (c *Context) RandomBytes(length int) (buffer []byte, err error) {
	if length <= 0 || length > 1024 {
		return nil, fmt.Errorf("length must be between 1 and 1024")
	}
	buffer = make([]byte, length)
	err = handleError(C.gpgme_op_random_bytes(c.ctx,
		C.GPGME_RANDOM_MODE_NORMAL,
		(*C.char)(unsafe.Pointer(&buffer[0])), C.size_t(length)))
	runtime.KeepAlive(c)
	if err != nil {
		return nil, err
	}
	return buffer, nil
}

// RandomZBase32 returns a random 30 characters long zBase32 string
// retrieved from gpg. (random mode GPGME_RANDOM_MODE_ZBASE32)
// The caller must provide a context ctx initialized for
// GPGME_PROTOCOL_OPENPGP.
// Since gpgme 2.0
func (c *Context) RandomZBase32() (zBase32Text string, err error) {
	buf := make([]byte, 31) // 30 characters + null terminator
	err = handleError(C.gpgme_op_random_bytes(c.ctx,
		C.GPGME_RANDOM_MODE_ZBASE32,
		(*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))))
	runtime.KeepAlive(c)
	if err != nil {
		return "", err
	}
	zBase32Text = strings.TrimRight(string(buf), "\x00")
	return zBase32Text, nil
}

// RandomValue returns an unbiased random value in the
// range 0 <= value < limit. The value is returned at value if and
// only if the function returns with success. The caller must also
// provide a context ctx initialized for GPGME_PROTOCOL_OPENPGP.
// Since gpgme 2.0
func (c *Context) RandomValue(limit uint32) (value uint32, err error) {
	if limit <= 0 {
		return 0, fmt.Errorf("limit must be greater than 0")
	}
	if limit == 1 {
		return 0, nil // Only one possible value, so return it directly
	}
	var retval C.ulong
	err = handleError(C.gpgme_op_random_value(c.ctx, C.ulong(limit), &retval))
	runtime.KeepAlive(c)
	if err != nil {
		return 0, err
	}
	value = uint32(retval)
	return value, nil
}
