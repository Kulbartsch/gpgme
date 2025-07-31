// Package gpgme provides a Go wrapper for the GPGME library
package gpgme

// #cgo pkg-config: gpgme
// #cgo CPPFLAGS: -D_FILE_OFFSET_BITS=64
// #include <stdlib.h>
// #include <gpgme.h>
// #include "go_gpgme.h"
import "C"
import (
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/cgo"
	"time"
	"unsafe"
)

var Version string

func init() {
	Version = C.GoString(C.gpgme_check_version(nil))
}

// Callback is the function that is called when a passphrase is required
type Callback func(uidHint string, prevWasBad bool, f *os.File) error

//export gogpgme_passfunc
func gogpgme_passfunc(hook unsafe.Pointer, uid_hint, passphrase_info *C.char, prev_was_bad, fd C.int) C.gpgme_error_t {
	h := *(*cgo.Handle)(hook)
	c := h.Value().(*Context)
	go_uid_hint := C.GoString(uid_hint)
	f := os.NewFile(uintptr(fd), go_uid_hint)
	defer f.Close()
	err := c.callback(go_uid_hint, prev_was_bad != 0, f)
	if err != nil {
		return C.GPG_ERR_CANCELED
	}
	return 0
}

type Protocol int

const (
	ProtocolOpenPGP  Protocol = C.GPGME_PROTOCOL_OpenPGP
	ProtocolCMS      Protocol = C.GPGME_PROTOCOL_CMS
	ProtocolGPGConf  Protocol = C.GPGME_PROTOCOL_GPGCONF
	ProtocolAssuan   Protocol = C.GPGME_PROTOCOL_ASSUAN
	ProtocolG13      Protocol = C.GPGME_PROTOCOL_G13
	ProtocolUIServer Protocol = C.GPGME_PROTOCOL_UISERVER
	ProtocolDefault  Protocol = C.GPGME_PROTOCOL_DEFAULT
	ProtocolUnknown  Protocol = C.GPGME_PROTOCOL_UNKNOWN
)

type PinEntryMode int

const (
	PinEntryDefault  PinEntryMode = C.GPGME_PINENTRY_MODE_DEFAULT
	PinEntryAsk      PinEntryMode = C.GPGME_PINENTRY_MODE_ASK
	PinEntryCancel   PinEntryMode = C.GPGME_PINENTRY_MODE_CANCEL
	PinEntryError    PinEntryMode = C.GPGME_PINENTRY_MODE_ERROR
	PinEntryLoopback PinEntryMode = C.GPGME_PINENTRY_MODE_LOOPBACK
)

type EncryptFlag uint

const (
	EncryptAlwaysTrust EncryptFlag = C.GPGME_ENCRYPT_ALWAYS_TRUST
	EncryptNoEncryptTo EncryptFlag = C.GPGME_ENCRYPT_NO_ENCRYPT_TO
	EncryptPrepare     EncryptFlag = C.GPGME_ENCRYPT_PREPARE
	EncryptExceptSign  EncryptFlag = C.GPGME_ENCRYPT_EXPECT_SIGN
	EncryptNoCompress  EncryptFlag = C.GPGME_ENCRYPT_NO_COMPRESS
	EncryptSymmetric   EncryptFlag = C.GPGME_ENCRYPT_SYMMETRIC
	EncryptThrowKeyIDs EncryptFlag = C.GPGME_ENCRYPT_THROW_KEYIDS
	EncryptWrap        EncryptFlag = C.GPGME_ENCRYPT_WRAP
	EncryptWantAddress EncryptFlag = C.GPGME_ENCRYPT_WANT_ADDRESS
	EncryptArchive     EncryptFlag = C.GPGME_ENCRYPT_ARCHIVE
	EncryptFile        EncryptFlag = C.GPGME_ENCRYPT_FILE // since 1.24.0
	EncryptAddRecp     EncryptFlag = C.GPGME_ENCRYPT_ADD_RECP
	EncryptChgRecp     EncryptFlag = C.GPGME_ENCRYPT_CHG_RECP
)

type KeySignFlag uint

const (
	KeySignLocal    KeySignFlag = C.GPGME_KEYSIGN_LOCAL
	KeySignLFSep    KeySignFlag = C.GPGME_KEYSIGN_LFSEP
	KeySignNoExpire KeySignFlag = C.GPGME_KEYSIGN_NOEXPIRE
	KeySignForce    KeySignFlag = C.GPGME_KEYSIGN_FORCE
)

type HashAlgo int

// const values for HashAlgo values should be added when necessary.

type KeyListMode uint

const (
	KeyListModeLocal        KeyListMode = C.GPGME_KEYLIST_MODE_LOCAL
	KeyListModeExtern       KeyListMode = C.GPGME_KEYLIST_MODE_EXTERN
	KeyListModeSigs         KeyListMode = C.GPGME_KEYLIST_MODE_SIGS
	KeyListModeSigNotations KeyListMode = C.GPGME_KEYLIST_MODE_SIG_NOTATIONS
	KeyListModeEphemeral    KeyListMode = C.GPGME_KEYLIST_MODE_EPHEMERAL
	KeyListModeModeValidate KeyListMode = C.GPGME_KEYLIST_MODE_VALIDATE
)

type PubkeyAlgo int

// const values for PubkeyAlgo values should be added when necessary.

// SigMode is used to specify the type of signature to create.
type SigMode int

const (
	// A normal signature is made, the output includes the plaintext and the signature
	SigModeNormal SigMode = C.GPGME_SIG_MODE_NORMAL
	// A detached signature is made.
	SigModeDetach SigMode = C.GPGME_SIG_MODE_DETACH
	// A clear text signature is made.  The ASCII armor and text mode settings
	// of the context are ignored.
	SigModeClear SigMode = C.GPGME_SIG_MODE_CLEAR
)

// SigSum is a bit vector giving a summary of the signature status
type SigSum int

// This are the bits giving a summary of the signature status.
const (
	// SigSumValid indicates that the signature is fully valid.
	SigSumValid SigSum = C.GPGME_SIGSUM_VALID
	// SigSumGreen indicates that the signature is good but one might want to
	// display some extra information.  Check the other bits.
	SigSumGreen SigSum = C.GPGME_SIGSUM_GREEN
	// SigSumRed indicates that signature is bad. It might be useful to check
	// other bits and display more information, i.e., a revoked certificate
	// might not render a signature invalid when the message was received
	// prior to the cause for the revocation.
	SigSumRed SigSum = C.GPGME_SIGSUM_RED
	// SigSumKeyRevoked indicates that the key or at least one certificate
	// has been revoked.
	SigSumKeyRevoked SigSum = C.GPGME_SIGSUM_KEY_REVOKED
	// SigSumKeyExpired indicates that the key or one of the certificates has
	// expired. It is probably a good idea to display the date of the expiration.
	SigSumKeyExpired SigSum = C.GPGME_SIGSUM_KEY_EXPIRED
	// SigSumSigExpired indicates that the signature itself has expired.
	SigSumSigExpired SigSum = C.GPGME_SIGSUM_SIG_EXPIRED
	// SigSumKeyMissing indicates that the message cannot be verified due to
	// a missing key or certificate.
	SigSumKeyMissing SigSum = C.GPGME_SIGSUM_KEY_MISSING
	// SigSumCRLMissing indicates that the CRL (or an equivalent mechanism)
	// is not available.
	SigSumCRLMissing SigSum = C.GPGME_SIGSUM_CRL_MISSING
	// SigSumCRLTooOld indicates that the CRL is too old to be used.
	SigSumCRLTooOld SigSum = C.GPGME_SIGSUM_CRL_TOO_OLD
	// SigSumBadPolicy indicates that a olicy requirement was not met.
	SigSumBadPolicy SigSum = C.GPGME_SIGSUM_BAD_POLICY
	// SigSumSysError indicates that a system error occurred.
	SigSumSysError SigSum = C.GPGME_SIGSUM_SYS_ERROR
)

type Validity int

const (
	ValidityUnknown   Validity = C.GPGME_VALIDITY_UNKNOWN
	ValidityUndefined Validity = C.GPGME_VALIDITY_UNDEFINED
	ValidityNever     Validity = C.GPGME_VALIDITY_NEVER
	ValidityMarginal  Validity = C.GPGME_VALIDITY_MARGINAL
	ValidityFull      Validity = C.GPGME_VALIDITY_FULL
	ValidityUltimate  Validity = C.GPGME_VALIDITY_ULTIMATE
)

type SignNotationFlags int

const (
	SignNotationHumanReadable SignNotationFlags = C.GPGME_SIG_NOTATION_HUMAN_READABLE
	SignNotationCritical      SignNotationFlags = C.GPGME_SIG_NOTATION_CRITICAL
)

type ErrorCode int

const (
	ErrorNoError ErrorCode = C.GPG_ERR_NO_ERROR
	ErrorEOF     ErrorCode = C.GPG_ERR_EOF
)

// DataType is used to return the detected type of the content of a data buffer.
type DataType int

const (
	TypeInvalid      DataType = C.GPGME_DATA_TYPE_INVALID       // This is returned by gpgme_data_identify if it was not possible to identify the data. Reasons for this might be a non-seekable stream or a memory problem.
	TypeUnknown      DataType = C.GPGME_DATA_TYPE_UNKNOWN       // The type of the data is not known.
	TypePGPSigned    DataType = C.GPGME_DATA_TYPE_PGP_SIGNED    // The data is an OpenPGP signed message. This may be a binary signature, a detached one or a cleartext signature.
	TypePGPEncrypted DataType = C.GPGME_DATA_TYPE_PGP_ENCRYPTED // The data is an OpenPGP encrypted message.
	TypePGPSignature DataType = C.GPGME_DATA_TYPE_PGP_SIGNATURE // The data is an OpenPGP detached signature.
	TypePGPOther     DataType = C.GPGME_DATA_TYPE_PGP_OTHER     // This is a generic OpenPGP message. In most cases this will be encrypted data.
	TypePGPKey       DataType = C.GPGME_DATA_TYPE_PGP_KEY       // This is an OpenPGP key (private or public).
	TypeCMSSigned    DataType = C.GPGME_DATA_TYPE_CMS_SIGNED    // This is a CMS signed message.
	TypeCMSEncrypted DataType = C.GPGME_DATA_TYPE_CMS_ENCRYPTED // This is a CMS encrypted (enveloped data) message.
	TypeCMSOther     DataType = C.GPGME_DATA_TYPE_CMS_OTHER     // This is used for other CMS message types.
	TypeX509Cert     DataType = C.GPGME_DATA_TYPE_X509_CERT     // The data is a X.509 certificate
	TypePKCS12       DataType = C.GPGME_DATA_TYPE_PKCS12        // The data is a PKCS#12 message. This is commonly used to exchange private keys for X.509.
)

// Error is a wrapper for GPGME errors
type Error struct {
	err C.gpgme_error_t
}

func (e Error) Code() ErrorCode {
	return ErrorCode(C.gpgme_err_code(e.err))
}

func (e Error) Error() string {
	return C.GoString(C.gpgme_strerror(e.err))
}

func handleError(err C.gpgme_error_t) error {
	e := Error{err: err}
	if e.Code() == ErrorNoError {
		return nil
	}
	return e
}

func cbool(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

// EngineCheckVersion verifies that the engine implementing the Protocol is
// installed in the expected path and meets the version requirement of GPGME.
func EngineCheckVersion(p Protocol) error {
	return handleError(C.gpgme_engine_check_version(C.gpgme_protocol_t(p)))
}

type EngineInfo struct {
	next            *EngineInfo
	protocol        Protocol
	fileName        string
	homeDir         string
	version         string
	requiredVersion string
}

func copyEngineInfo(info C.gpgme_engine_info_t) *EngineInfo {
	res := &EngineInfo{
		next:            nil,
		protocol:        Protocol(info.protocol),
		fileName:        C.GoString(info.file_name),
		homeDir:         C.GoString(info.home_dir),
		version:         C.GoString(info.version),
		requiredVersion: C.GoString(info.req_version),
	}
	if info.next != nil {
		res.next = copyEngineInfo(info.next)
	}
	return res
}

func (e *EngineInfo) Next() *EngineInfo {
	return e.next
}

func (e *EngineInfo) Protocol() Protocol {
	return e.protocol
}

func (e *EngineInfo) FileName() string {
	return e.fileName
}

func (e *EngineInfo) Version() string {
	return e.version
}

func (e *EngineInfo) RequiredVersion() string {
	return e.requiredVersion
}

func (e *EngineInfo) HomeDir() string {
	return e.homeDir
}

// GetEngineInfo returns a structure of EngineInfo
func GetEngineInfo() (*EngineInfo, error) {
	var cInfo C.gpgme_engine_info_t
	err := handleError(C.gpgme_get_engine_info(&cInfo))
	if err != nil {
		return nil, err
	}
	return copyEngineInfo(cInfo), nil // It is up to the caller not to invalidate cInfo concurrently until this is done.
}

func SetEngineInfo(proto Protocol, fileName, homeDir string) error {
	var cfn, chome *C.char
	if fileName != "" {
		cfn = C.CString(fileName)
		defer C.free(unsafe.Pointer(cfn))
	}
	if homeDir != "" {
		chome = C.CString(homeDir)
		defer C.free(unsafe.Pointer(chome))
	}
	return handleError(C.gpgme_set_engine_info(C.gpgme_protocol_t(proto), cfn, chome))
}

// GetDirInfo returns a statically allocated string with the value
// associated to what.  The returned values are the defaults and
// won’t change even after gpgme_set_engine_info has been used to
// configure a different engine. NULL is returned if no value is
// available. Commonly supported values for what are:
//
//   - "homedir" - Return the default home directory.
//   - "sysconfdir" - Return the name of the system configuration directory
//   - "bindir" - Return the name of the directory with GnuPG program files.
//   - "libdir" - Return the name of the directory with GnuPG related library files.
//   - "libexecdir" - Return the name of the directory with GnuPG helper program files.
//   - "datadir" - Return the name of the directory with GnuPG shared data.
//   - "localedir" - Return the name of the directory with GnuPG locale data.
//   - "socketdir" - Return the name of the directory with the following sockets.
//   - "agent-socket" - Return the name of the socket to connect to the gpg-agent.
//   - "agent-ssh-socket" - Return the name of the socket to connect to the ssh-agent component of gpg-agent.
//   - "dirmngr-socket" - Return the name of the socket to connect to the dirmngr.
//   - "uiserver-socket" - Return the name of the socket to connect to the user interface server.
//   - "gpgconf-name" - Return the file name of the engine configuration tool.
//   - "gpg-name" - Return the file name of the OpenPGP engine.
//   - "gpgsm-name" - Return the file name of the CMS engine.
//   - "g13-name" - Return the name of the file container encryption engine.
//   - "keyboxd-name" - Return the name of the key database daemon.
//   - "agent-name" - Return the name of gpg-agent.
//   - "scdaemon-name" - Return the name of the smart card daemon.
//   - "dirmngr-name" - Return the name of dirmngr.
//   - "pinentry-name" - Return the name of the pinentry program.
//   - "gpg-wks-client-name" - Return the name of the Web Key Service tool.
//   - "gpgtar-name" - Return the name of the gpgtar program.
//
// For more information see
// https://www.gnupg.org/documentation/manuals/gpgme/Engine-Version-Check.html
func GetDirInfo(what string) string {
	var cWhat *C.char
	if what != "" {
		cWhat = C.CString(what)
		defer C.free(unsafe.Pointer(cWhat))
	}
	cDir := C.gpgme_get_dirinfo(cWhat)
	return C.GoString(cDir)
}

func FindKeys(pattern string, secretOnly bool) ([]*Key, error) {
	var keys []*Key
	ctx, err := New()
	if err != nil {
		return keys, err
	}
	defer ctx.Release()
	if err := ctx.KeyListStart(pattern, secretOnly); err != nil {
		return keys, err
	}
	defer func() { _ = ctx.KeyListEnd() }()
	for ctx.KeyListNext() {
		keys = append(keys, ctx.Key)
	}
	if ctx.KeyError != nil {
		return keys, ctx.KeyError
	}
	return keys, nil
}

func Decrypt(r io.Reader) (*Data, error) {
	ctx, err := New()
	if err != nil {
		return nil, err
	}
	defer ctx.Release()
	cipher, err := NewDataReader(r)
	if err != nil {
		return nil, err
	}
	defer cipher.Close()
	plain, err := NewData()
	if err != nil {
		return nil, err
	}
	if err := ctx.Decrypt(cipher, plain); err != nil {
		return nil, err
	}
	_, err = plain.Seek(0, SeekSet)
	return plain, err
}

// -- context --

// IDEA: should be named ContextType
type Context struct {
	Key      *Key
	KeyError error

	callback Callback
	cbc      cgo.Handle // WARNING: Call runtime.KeepAlive(c) after ANY use of c.cbc in C (typically via c.ctx)

	ctx C.gpgme_ctx_t // WARNING: Call runtime.KeepAlive(c) after ANY passing of c.ctx to C
}

func New() (*Context, error) {
	c := &Context{}
	err := C.gpgme_new(&c.ctx)
	runtime.SetFinalizer(c, (*Context).Release)
	return c, handleError(err)
}

func (c *Context) Release() {
	if c.ctx == nil {
		return
	}
	if c.cbc > 0 {
		c.cbc.Delete()
	}
	C.gpgme_release(c.ctx)
	runtime.KeepAlive(c)
	c.ctx = nil
}

func (c *Context) SetArmor(yes bool) {
	C.gpgme_set_armor(c.ctx, cbool(yes))
	runtime.KeepAlive(c)
}

func (c *Context) Armor() bool {
	res := C.gpgme_get_armor(c.ctx) != 0
	runtime.KeepAlive(c)
	return res
}

func (c *Context) SetTextMode(yes bool) {
	C.gpgme_set_textmode(c.ctx, cbool(yes))
	runtime.KeepAlive(c)
}

func (c *Context) TextMode() bool {
	res := C.gpgme_get_textmode(c.ctx) != 0
	runtime.KeepAlive(c)
	return res
}

func (c *Context) SetProtocol(p Protocol) error {
	err := handleError(C.gpgme_set_protocol(c.ctx, C.gpgme_protocol_t(p)))
	runtime.KeepAlive(c)
	return err
}

func (c *Context) Protocol() Protocol {
	res := Protocol(C.gpgme_get_protocol(c.ctx))
	runtime.KeepAlive(c)
	return res
}

func (c *Context) SetKeyListMode(m KeyListMode) error {
	err := handleError(C.gpgme_set_keylist_mode(c.ctx, C.gpgme_keylist_mode_t(m)))
	runtime.KeepAlive(c)
	return err
}

func (c *Context) KeyListMode() KeyListMode {
	res := KeyListMode(C.gpgme_get_keylist_mode(c.ctx))
	runtime.KeepAlive(c)
	return res
}

func (c *Context) SetPinEntryMode(m PinEntryMode) error {
	err := handleError(C.gpgme_set_pinentry_mode(c.ctx, C.gpgme_pinentry_mode_t(m)))
	runtime.KeepAlive(c)
	return err
}

func (c *Context) PinEntryMode() PinEntryMode {
	res := PinEntryMode(C.gpgme_get_pinentry_mode(c.ctx))
	runtime.KeepAlive(c)
	return res
}

func (c *Context) SetCallback(callback Callback) error {
	var err error
	c.callback = callback
	if c.cbc > 0 {
		c.cbc.Delete()
	}
	if callback != nil {
		c.cbc = cgo.NewHandle(c)
		_, err = C.gpgme_set_passphrase_cb(c.ctx, C.gpgme_passphrase_cb_t(C.gogpgme_passfunc), unsafe.Pointer(&c.cbc))
	} else {
		c.cbc = 0
		_, err = C.gpgme_set_passphrase_cb(c.ctx, nil, nil)
	}
	runtime.KeepAlive(c)
	return err
}

// EngineInfo returns a linked list of type EngineInfo.  Each info structure
// describes the defaults of one configured backend.
func (c *Context) EngineInfo() *EngineInfo {
	cInfo := C.gpgme_ctx_get_engine_info(c.ctx)
	runtime.KeepAlive(c)
	// NOTE: c must be live as long as we are accessing cInfo.
	res := copyEngineInfo(cInfo)
	runtime.KeepAlive(c) // for accesses to cInfo
	return res
}

// SignersAdd sets a key for signing.
func (c *Context) SignersAdd(key *Key) error {
	err := handleError(C.gpgme_signers_add(c.ctx, key.k))
	runtime.KeepAlive(c)
	runtime.KeepAlive(key)
	return err
}

// SetEngineInfo changes the configuration of the crypto engine implementing
// the protocol proto for the context.  fileName is the file name of the
// executable program implementing this protocol, and homeDir is the directory
// name of the configuration directory for this crypto engine.
// If homeDir is empty, the engine’s default will be used.
// Currently this function must be used before starting the first crypto
// operation.  It is unspecified if and when the changes will take effect if
// the function is called after starting the first operation on the context.
func (c *Context) SetEngineInfo(proto Protocol, fileName, homeDir string) error {
	var cfn, chome *C.char
	if fileName != "" {
		cfn = C.CString(fileName)
		defer C.free(unsafe.Pointer(cfn))
	}
	if homeDir != "" {
		chome = C.CString(homeDir)
		defer C.free(unsafe.Pointer(chome))
	}
	err := handleError(C.gpgme_ctx_set_engine_info(c.ctx, C.gpgme_protocol_t(proto), cfn, chome))
	runtime.KeepAlive(c)
	return err
}

func (c *Context) KeyListStart(pattern string, secretOnly bool) error {
	cpattern := C.CString(pattern)
	defer C.free(unsafe.Pointer(cpattern))
	err := handleError(C.gpgme_op_keylist_start(c.ctx, cpattern, cbool(secretOnly)))
	runtime.KeepAlive(c)
	return err
}

func (c *Context) KeyListNext() bool {
	c.Key = newKey()
	err := handleError(C.gpgme_op_keylist_next(c.ctx, &c.Key.k))
	runtime.KeepAlive(c) // implies runtime.KeepAlive(c.Key)
	if err != nil {
		if e, ok := err.(Error); ok && e.Code() == ErrorEOF {
			c.KeyError = nil
		} else {
			c.KeyError = err
		}
		return false
	}
	c.KeyError = nil
	return true
}

func (c *Context) KeyListEnd() error {
	err := handleError(C.gpgme_op_keylist_end(c.ctx))
	runtime.KeepAlive(c)
	return err
}

// GetKey fetches the key with the fingerprint (or key ID) from the crypto
// backend and return it in r key. If secret is true, you get the secret key.
// The currently active keylist mode is used to retrieve the key. The key will
// have one reference for the user.
func (c *Context) GetKey(fingerprint string, secret bool) (*Key, error) {
	key := newKey()
	cfpr := C.CString(fingerprint)
	defer C.free(unsafe.Pointer(cfpr))
	err := handleError(C.gpgme_get_key(c.ctx, cfpr, &key.k, cbool(secret)))
	runtime.KeepAlive(c)
	runtime.KeepAlive(key)
	keyKIsNil := key.k == nil
	runtime.KeepAlive(key)
	if e, ok := err.(Error); keyKIsNil && ok && e.Code() == ErrorEOF {
		return nil, fmt.Errorf("key %q not found", fingerprint)
	}
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Decrypt decrypts the ciphertext or, if a file name is set on the data
// object, the ciphertext stored in the corresponding file.  The decrypted
// ciphertext is stored into the data object plain or written to the file set
// with SetFileName for plaintext.
// The function returns the error GPG_ERR_NO_ERROR if the ciphertext could be
// decrypted successfully, GPG_ERR_INV_VALUE if context, cipher or plain is
// not a valid pointer, GPG_ERR_NO_DATA if cipher does not contain any data to
// decrypt, GPG_ERR_DECRYPT_FAILED if cipher is not a valid cipher text,
// GPG_ERR_BAD_PASSPHRASE if the passphrase for the secret key could not be
// retrieved, and passes through some errors that are reported by the crypto
// engine support routines.
func (c *Context) Decrypt(ciphertext, plaintext *Data) error {
	err := handleError(C.gpgme_op_decrypt(c.ctx, ciphertext.dh, plaintext.dh))
	runtime.KeepAlive(c)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(plaintext)
	return err
}

// DecryptVerify decrypts the ciphertext in the data object ciphertext and
// stores it into the data object plaintext.
// If cipher contains signatures, they will be verified.
// After the operation completed, DecryptResult and VerifyResult can be used to
// retrieve more information about result of the operation.
func (c *Context) DecryptVerify(ciphertext, plaintext *Data) error {
	err := handleError(C.gpgme_op_decrypt_verify(c.ctx, ciphertext.dh, plaintext.dh))
	runtime.KeepAlive(c)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(plaintext)
	return err
}

// Recipient is a structure used to store information about the recipient of an
// decryption operation.
// IDEA: should be named RecipientType
type Recipient struct {
	PubkeyAlgo PubkeyAlgo
	KeyID      string
	Status     error
}

// DecryptResultType is a structure that stores the result of a decrypt
// operation.  After successfully decrypting data, you can retrieve the
// result with DecryptResult.
type DecryptResultType struct {
	// If an unsupported algorithm was encountered, this string describes the
	// algorithm that is not supported.
	UnsupportedAlgorithm string
	// This is true if the key was not used according to its policy. (Since GPGME: 0.9.0)
	WrongKeyUsage bool
	// The message was made by a legacy algorithm without any integrity
	// protection (no manipulation detection code).  This might be an old but
	// legitimate message.  (Since GPGME: 1.11.2)
	LegacyCipherNoMDC bool
	// The message claims that the content is a MIME object. (Since GPGME: 1.11.0)
	IsMIME bool
	// The message was encrypted in a VS-NfD compliant way. This is a
	// specification in Germany (DE) for a restricted and EU/NATO RESTRICTED
	// communication level. (Since GPGME: 1.10.0)
	IsDEVS bool
	// The compliance flags (e.g. is de vs) are set but the software has not
	// yet been approved or is in a beta state. (Since GPGME: 1.24.0)
	BetaCompliance bool
	// This is a linked list of recipients to which this message was encrypted.
	// (Since GPGME: 1.1.0)
	Recipients []Recipient
	// This is the filename of the original plaintext message file if it is
	// known, otherwise this is empty.
	Filename string
	// A textual representation of the session key used in symmetric encryption
	// of the message, if the context has been set to export session keys
	// [(see gpgme_set_ctx_flag, "export-session-key"),]
	// and a session key was available for the most recent decryption operation.
	// Otherwise, this is empty. (Since GPGME: 1.8.0)
	// [You must not try to access this member of the struct unless
	// gpgme_set_ctx_flag (ctx, "export-session-key") returns
	// success or gpgme_get_ctx_flag (ctx, "export-session-key") returns true.]
	SessionKey string
	// A string with the symmetric encryption algorithm and mode using the
	// format "<algo>.<mode>". Note that the deprecated non-MDC encryption
	// mode of OpenPGP is given as "PGPCFB". (Since GPGME: 1.11.0)
	SymkeyAlgo string
}

// DecryptResult returns the result of the last decryption operation on the
// context.  The result is a structure of type DecryptResultType.
func (c *Context) DecryptResult() (decrRes DecryptResultType, err error) {
	res := C.gpgme_op_decrypt_result(c.ctx)
	if res == nil {
		return decrRes, fmt.Errorf("gpgme_op_decrypt_result returned nil")
	}
	runtime.KeepAlive(c)
	decrRes.UnsupportedAlgorithm = C.GoString(res.unsupported_algorithm)
	decrRes.WrongKeyUsage = C.decrypt_result_wrong_key_usage(res) != 0
	decrRes.LegacyCipherNoMDC = C.decrypt_result_legacy_cipher(res) != 0
	decrRes.IsMIME = C.decrypt_result_is_mime(res) != 0
	decrRes.IsDEVS = C.decrypt_result_is_restricted(res) != 0
	decrRes.BetaCompliance = C.decrypt_result_beta_compliance(res) != 0
	decrRes.Filename = C.GoString(res.file_name)
	decrRes.SessionKey = C.GoString(res.session_key)
	decrRes.SymkeyAlgo = C.GoString(res.symkey_algo)

	// Recipients
	a := res.recipients
	for a != nil {
		rec := Recipient{
			PubkeyAlgo: PubkeyAlgo(a.pubkey_algo),
			KeyID:      C.GoString(a.keyid),
			Status:     handleError(a.status),
		}
		decrRes.Recipients = append(decrRes.Recipients, rec)
		a = a.next
	}
	return
}

// Signature is a structure that stores information about a signature
// that was made on a message.  If the corresponding validation failed,
// this might be null.
// IDEA: should be named SignatureType
type Signature struct {
	// Summary is a bit vector giving a summary of the signature status.
	// It provides an easy interface to a defined semantic of the signature
	// status.  Checking just one bit is sufficient to see whether a signature
	// is valid without any restrictions. This means that you can check for
	// ...Summary & gpgme.SigSumValid
	Summary SigSum
	// Fingerprint of the key that was used to sign the data.
	Fingerprint string
	// Status of the signature.
	Status error
	// TODO: notations
	// Timestamp of the creation of the signature.
	Timestamp time.Time
	// ExpTimestamp is the expiration timestamp of the signature.
	ExpTimestamp time.Time
	// WrongKeyUsage is true if the key was not used according to its policy.
	WrongKeyUsage bool
	// PKATrust s set to the trust information gained by means of the PKA
	// system.  Values are
	//   - 0: No PKA information available or verification not possible.
	//   - 1: PKA verification failed.
	//   - 2: PKA verification succeeded.
	//   - 3: Reserved for future use.
	PKATrust uint
	// ChainModel s true if the validity of the signature has been checked using
	// the chain model. In the chain model the time the signature has been
	// created must be within the validity period of the certificate and the
	// time the certificate itself has been created must be within the validity
	// period of the issuing certificate. In contrast the default validation
	// model checks the validity of signature as well at the entire certificate
	// chain at the current time.
	ChainModel bool
	// ... is true when signature was created in a VS-NfD compliant way.
	// This is a specification in Germany for a restricted communication level.
	// avaiable since: 1.10.0)
	// TODO: is_de_vs
	// ...
	// TODO: beta_compliance
	// Validity of the signature.
	Validity Validity
	// ValidityReason provides a reason why the signature is not valid.
	ValidityReason error
	// PubkeyAlgo is the public key algorithm used to create the signature.
	PubkeyAlgo PubkeyAlgo
	// HashAlgo is the hash algorithm used to create the signature.
	HashAlgo HashAlgo
	// TODO: pka_address
	// TODO: gpgme_key_t
}

// VerifyResult returns results on the last operation on the context,
// which must have been a verify operation.
// It returns the filename (string) of the signed file (if any),
// the signatures (array of type Signature) or an error.
func (c *Context) VerifyResult() (filename string, sigs []Signature, err error) {
	res := C.gpgme_op_verify_result(c.ctx)
	runtime.KeepAlive(c)
	// sigs := []Signature{}
	for s := res.signatures; s != nil; s = s.next {
		sig := Signature{
			Summary:     SigSum(s.summary),
			Fingerprint: C.GoString(s.fpr),
			Status:      handleError(s.status),
			// TODO: s.notations not implemented
			Timestamp:      time.Unix(int64(s.timestamp), 0),
			ExpTimestamp:   time.Unix(int64(s.exp_timestamp), 0),
			WrongKeyUsage:  C.signature_wrong_key_usage(s) != 0,
			PKATrust:       uint(C.signature_pka_trust(s)),
			ChainModel:     C.signature_chain_model(s) != 0,
			Validity:       Validity(s.validity),
			ValidityReason: handleError(s.validity_reason),
			PubkeyAlgo:     PubkeyAlgo(s.pubkey_algo),
			HashAlgo:       HashAlgo(s.hash_algo),
		}
		sigs = append(sigs, sig)
	}
	fileName := C.GoString(res.file_name)
	runtime.KeepAlive(c) // for all accesses to res above
	return fileName, sigs, nil
}

// Verfify verifies that the signature in the data object sig is a valid
// signature.
// If sig is a detached signature, then the signed text should be provided in
// signedText and plain should be a pointer. Otherwise, if sig is a normal
// (or cleartext) signature, signed text should be nil and plain should be a
// writable data object that will contain the plaintext after successful
// verification.
// If a file name is set on the data object sig (or on the data object signed
// text), then the data of the signature (resp. the data of the signed text)
// is not read from the data object but from the file with the given file name.
// If a file name is set on the data object plain then the plaintext is not
// stored in the data object but it is written to a file with the given
// filename.
// Verify returns the filename (string) of the signed file (if any),
// the signatures (array of type Signature) and an error.
func (c *Context) Verify(sig, signedText, plain *Data) (string, []Signature, error) {
	var signedTextPtr, plainPtr C.gpgme_data_t = nil, nil
	if signedText != nil {
		signedTextPtr = signedText.dh
	}
	if plain != nil {
		plainPtr = plain.dh
	}
	err := handleError(C.gpgme_op_verify(c.ctx, sig.dh, signedTextPtr, plainPtr))
	runtime.KeepAlive(c)
	runtime.KeepAlive(sig)
	if signedText != nil {
		runtime.KeepAlive(signedText)
	}
	if plain != nil {
		runtime.KeepAlive(plain)
	}
	if err != nil {
		return "", nil, err
	}

	fileName, sigs, err := c.VerifyResult()
	if err != nil {
		return "", nil, err
	}
	runtime.KeepAlive(c) // for all accesses to res above
	return fileName, sigs, nil
	/* The following is replaced by the VerifyResult factored out above.
	   This is kept for reference and will be removed in a future version.
	res := C.gpgme_op_verify_result(c.ctx)
	runtime.KeepAlive(c)
	// NOTE: c must be live as long as we are accessing res.
	sigs := []Signature{}
	for s := res.signatures; s != nil; s = s.next {
		sig := Signature{
			Summary:     SigSum(s.summary),
			Fingerprint: C.GoString(s.fpr),
			Status:      handleError(s.status),
			// s.notations not implemented
			Timestamp:      time.Unix(int64(s.timestamp), 0),
			ExpTimestamp:   time.Unix(int64(s.exp_timestamp), 0),
			WrongKeyUsage:  C.signature_wrong_key_usage(s) != 0,
			PKATrust:       uint(C.signature_pka_trust(s)),
			ChainModel:     C.signature_chain_model(s) != 0,
			Validity:       Validity(s.validity),
			ValidityReason: handleError(s.validity_reason),
			PubkeyAlgo:     PubkeyAlgo(s.pubkey_algo),
			HashAlgo:       HashAlgo(s.hash_algo),
		}
		sigs = append(sigs, sig)
	}
	fileName := C.GoString(res.file_name)
	*/
}

func (c *Context) Encrypt(recipients []*Key, flags EncryptFlag, plaintext, ciphertext *Data) error {
	size := unsafe.Sizeof(new(C.gpgme_key_t))
	recp := C.calloc(C.size_t(len(recipients)+1), C.size_t(size))
	defer C.free(recp)
	for i := range recipients {
		ptr := (*C.gpgme_key_t)(unsafe.Pointer(uintptr(recp) + size*uintptr(i)))
		*ptr = recipients[i].k
	}
	err := C.gpgme_op_encrypt(c.ctx, (*C.gpgme_key_t)(recp), C.gpgme_encrypt_flags_t(flags), plaintext.dh, ciphertext.dh)
	runtime.KeepAlive(c)
	runtime.KeepAlive(recipients)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(ciphertext)
	return handleError(err)
}

func (c *Context) Sign(signers []*Key, plain, sig *Data, mode SigMode) error {
	C.gpgme_signers_clear(c.ctx)
	runtime.KeepAlive(c)
	for _, k := range signers {
		err := handleError(C.gpgme_signers_add(c.ctx, k.k))
		runtime.KeepAlive(c)
		runtime.KeepAlive(k)
		if err != nil {
			C.gpgme_signers_clear(c.ctx)
			runtime.KeepAlive(c)
			return err
		}
	}
	err := handleError(C.gpgme_op_sign(c.ctx, plain.dh, sig.dh, C.gpgme_sig_mode_t(mode)))
	runtime.KeepAlive(c)
	runtime.KeepAlive(plain)
	runtime.KeepAlive(sig)
	return err
}

func (c *Context) EncryptSign(recipients []*Key, flags EncryptFlag, plaintext, ciphertext *Data) error {
	size := unsafe.Sizeof(new(C.gpgme_key_t))
	recp := C.calloc(C.size_t(len(recipients)+1), C.size_t(size))
	defer C.free(recp)
	for i := range recipients {
		ptr := (*C.gpgme_key_t)(unsafe.Pointer(uintptr(recp) + size*uintptr(i)))
		*ptr = recipients[i].k
	}
	err := C.gpgme_op_encrypt_sign(c.ctx, (*C.gpgme_key_t)(recp),
		C.gpgme_encrypt_flags_t(flags), plaintext.dh, ciphertext.dh)
	runtime.KeepAlive(c)
	runtime.KeepAlive(recipients)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(ciphertext)
	return handleError(err)
}

// TODO: implement gpgme_op_sign_result

// KeySign adds a new key signature to the public key *key*.
//
// The common case is to use the default key for signing other keys.
// If another key or more than one key shall be used for a key signature,
// (Context) SignersAdd can be used.  The user ID to be signed is specified by
// *u* and must be given verbatim as it appears in the key.
//
// The duration to expiration of the signature is specified by *expires*.
// If *expires* is zero, the default expiration time as defined in gpg.conf
// with *default-sig-expire* is used.
// If the flag *KeySignNoExpire* is set the signature will not expire.
// The flags are used to specify the type of signature to create.
// The flags can be combined with the bitwise OR operator.
//
// HINT: Using an empty string for *u* to create signatures for all user IDs
// will only work with gpgme versions younger than 2023-05.
func (c *Context) KeySign(key Key, u string, expires time.Duration, flags KeySignFlag) error {
	cur := C.CString(u)
	defer C.free(unsafe.Pointer(cur))
	expiresOn := uint64(time.Now().Add(expires).Unix())
	err := C.gpgme_op_keysign(c.ctx, key.k, cur,
		C.ulong(uint64(expiresOn)), C.uint(flags))
	runtime.KeepAlive(c)
	runtime.KeepAlive(key)
	return handleError(err)
}

type AssuanDataCallback func(data []byte) error
type AssuanInquireCallback func(name, args string) error
type AssuanStatusCallback func(status, args string) error

// AssuanSend sends a raw Assuan command to gpg-agent
func (c *Context) AssuanSend(
	cmd string,
	data AssuanDataCallback,
	inquiry AssuanInquireCallback,
	status AssuanStatusCallback,
) error {
	var operr C.gpgme_error_t

	dataPtr := cgo.NewHandle(&data)
	inquiryPtr := cgo.NewHandle(&inquiry)
	statusPtr := cgo.NewHandle(&status)
	cmdCStr := C.CString(cmd)
	defer C.free(unsafe.Pointer(cmdCStr))
	err := C.gogpgme_op_assuan_transact_ext(
		c.ctx,
		cmdCStr,
		unsafe.Pointer(&dataPtr),
		unsafe.Pointer(&inquiryPtr),
		unsafe.Pointer(&statusPtr),
		&operr,
	)
	runtime.KeepAlive(c)

	if handleError(operr) != nil {
		return handleError(operr)
	}
	return handleError(err)
}

//export gogpgme_assuan_data_callback
func gogpgme_assuan_data_callback(handle unsafe.Pointer, data unsafe.Pointer, datalen C.size_t) C.gpgme_error_t {
	h := *(*cgo.Handle)(handle)
	c := h.Value().(*AssuanDataCallback)
	if *c == nil {
		return 0
	}
	if err := (*c)(C.GoBytes(data, C.int(datalen))); err != nil {
		return C.gpgme_error(C.GPG_ERR_USER_1)
	}
	return 0
}

//export gogpgme_assuan_inquiry_callback
func gogpgme_assuan_inquiry_callback(handle unsafe.Pointer, cName *C.char, cArgs *C.char) C.gpgme_error_t {
	name := C.GoString(cName)
	args := C.GoString(cArgs)
	h := *(*cgo.Handle)(handle)
	c := h.Value().(*AssuanInquireCallback)
	if *c == nil {
		return 0
	}
	if err := (*c)(name, args); err != nil {
		return C.gpgme_error(C.GPG_ERR_USER_1)
	}
	return 0
}

//export gogpgme_assuan_status_callback
func gogpgme_assuan_status_callback(handle unsafe.Pointer, cStatus *C.char, cArgs *C.char) C.gpgme_error_t {
	status := C.GoString(cStatus)
	args := C.GoString(cArgs)
	h := *(*cgo.Handle)(handle)
	c := h.Value().(*AssuanStatusCallback)
	if *c == nil {
		return 0
	}
	if err := (*c)(status, args); err != nil {
		return C.gpgme_error(C.GPG_ERR_USER_1)
	}
	return 0
}

// ExportModeFlags defines how keys are exported from Export
type ExportModeFlags uint

const (
	ExportModeExtern  ExportModeFlags = C.GPGME_EXPORT_MODE_EXTERN
	ExportModeMinimal ExportModeFlags = C.GPGME_EXPORT_MODE_MINIMAL
)

func (c *Context) Export(pattern string, mode ExportModeFlags, data *Data) error {
	var err error
	pat := C.CString(pattern)
	defer C.free(unsafe.Pointer(pat))
	if data == nil {
		err = handleError(C.gpgme_op_export(c.ctx, pat, C.gpgme_export_mode_t(mode), nil))
	} else {
		err = handleError(C.gpgme_op_export(c.ctx, pat, C.gpgme_export_mode_t(mode), data.dh))
	}
	runtime.KeepAlive(c)
	runtime.KeepAlive(data)
	return err
}

// ImportStatusFlags describes the type of ImportStatus.Status. The C API in gpgme.h simply uses "unsigned".
type ImportStatusFlags uint

const (
	ImportNew    ImportStatusFlags = C.GPGME_IMPORT_NEW
	ImportUID    ImportStatusFlags = C.GPGME_IMPORT_UID
	ImportSIG    ImportStatusFlags = C.GPGME_IMPORT_SIG
	ImportSubKey ImportStatusFlags = C.GPGME_IMPORT_SUBKEY
	ImportSecret ImportStatusFlags = C.GPGME_IMPORT_SECRET
)

type ImportStatus struct {
	Fingerprint string
	Result      error
	Status      ImportStatusFlags
}

type ImportResult struct {
	Considered      int
	NoUserID        int
	Imported        int
	ImportedRSA     int
	Unchanged       int
	NewUserIDs      int
	NewSubKeys      int
	NewSignatures   int
	NewRevocations  int
	SecretRead      int
	SecretImported  int
	SecretUnchanged int
	NotImported     int
	Imports         []ImportStatus
}

func (c *Context) Import(keyData *Data) (*ImportResult, error) {
	err := handleError(C.gpgme_op_import(c.ctx, keyData.dh))
	runtime.KeepAlive(c)
	runtime.KeepAlive(keyData)
	if err != nil {
		return nil, err
	}
	res := C.gpgme_op_import_result(c.ctx)
	runtime.KeepAlive(c)
	// NOTE: c must be live as long as we are accessing res.
	imports := []ImportStatus{}
	for s := res.imports; s != nil; s = s.next {
		imports = append(imports, ImportStatus{
			Fingerprint: C.GoString(s.fpr),
			Result:      handleError(s.result),
			Status:      ImportStatusFlags(s.status),
		})
	}
	importResult := &ImportResult{
		Considered:      int(res.considered),
		NoUserID:        int(res.no_user_id),
		Imported:        int(res.imported),
		ImportedRSA:     int(res.imported_rsa),
		Unchanged:       int(res.unchanged),
		NewUserIDs:      int(res.new_user_ids),
		NewSubKeys:      int(res.new_sub_keys),
		NewSignatures:   int(res.new_signatures),
		NewRevocations:  int(res.new_revocations),
		SecretRead:      int(res.secret_read),
		SecretImported:  int(res.secret_imported),
		SecretUnchanged: int(res.secret_unchanged),
		NotImported:     int(res.not_imported),
		Imports:         imports,
	}
	runtime.KeepAlive(c) // for all accesses to res above
	return importResult, nil
}

// -- key --

type Key struct {
	k C.gpgme_key_t // WARNING: Call Runtime.KeepAlive(k) after ANY passing of k.k to C
}

func newKey() *Key {
	k := &Key{}
	runtime.SetFinalizer(k, (*Key).Release)
	return k
}

func (k *Key) Release() {
	C.gpgme_key_release(k.k)
	runtime.KeepAlive(k)
	k.k = nil
}

func (k *Key) Revoked() bool {
	res := C.key_revoked(k.k) != 0
	runtime.KeepAlive(k)
	return res
}

func (k *Key) Expired() bool {
	res := C.key_expired(k.k) != 0
	runtime.KeepAlive(k)
	return res
}

func (k *Key) Disabled() bool {
	res := C.key_disabled(k.k) != 0
	runtime.KeepAlive(k)
	return res
}

func (k *Key) Invalid() bool {
	res := C.key_invalid(k.k) != 0
	runtime.KeepAlive(k)
	return res
}

func (k *Key) CanEncrypt() bool {
	res := C.key_can_encrypt(k.k) != 0
	runtime.KeepAlive(k)
	return res
}

func (k *Key) CanSign() bool {
	res := C.key_can_sign(k.k) != 0
	runtime.KeepAlive(k)
	return res
}

func (k *Key) CanCertify() bool {
	res := C.key_can_certify(k.k) != 0
	runtime.KeepAlive(k)
	return res
}

func (k *Key) Secret() bool {
	res := C.key_secret(k.k) != 0
	runtime.KeepAlive(k)
	return res
}

func (k *Key) CanAuthenticate() bool {
	res := C.key_can_authenticate(k.k) != 0
	runtime.KeepAlive(k)
	return res
}

func (k *Key) IsQualified() bool {
	res := C.key_is_qualified(k.k) != 0
	runtime.KeepAlive(k)
	return res
}

func (k *Key) Protocol() Protocol {
	res := Protocol(k.k.protocol)
	runtime.KeepAlive(k)
	return res
}

func (k *Key) IssuerSerial() string {
	res := C.GoString(k.k.issuer_serial)
	runtime.KeepAlive(k)
	return res
}

func (k *Key) IssuerName() string {
	res := C.GoString(k.k.issuer_name)
	runtime.KeepAlive(k)
	return res
}

func (k *Key) ChainID() string {
	res := C.GoString(k.k.chain_id)
	runtime.KeepAlive(k)
	return res
}

func (k *Key) OwnerTrust() Validity {
	res := Validity(k.k.owner_trust)
	runtime.KeepAlive(k)
	return res
}

func (k *Key) SubKeys() *SubKey {
	subKeys := k.k.subkeys
	runtime.KeepAlive(k)
	if subKeys == nil {
		return nil
	}
	return &SubKey{k: subKeys, parent: k} // The parent: k reference ensures subKeys remains valid
}

func (k *Key) UserIDs() *UserID {
	uids := k.k.uids
	runtime.KeepAlive(k)
	if uids == nil {
		return nil
	}
	return &UserID{u: uids, parent: k} // The parent: k reference ensures uids remains valid
}

func (k *Key) HasUserIDs() bool {
	uids := k.k.uids
	runtime.KeepAlive(k)
	return uids != nil
}

func (k *Key) KeyListMode() KeyListMode {
	res := KeyListMode(k.k.keylist_mode)
	runtime.KeepAlive(k)
	return res
}

func (k *Key) Fingerprint() string {
	res := C.GoString(k.k.fpr)
	runtime.KeepAlive(k)
	return res
}

// -- subkey --

type SubKey struct {
	k      C.gpgme_subkey_t
	parent *Key // make sure the key is not released when we have a reference to a subkey
}

func (k *SubKey) Next() *SubKey {
	if k.k.next == nil {
		return nil
	}
	return &SubKey{k: k.k.next, parent: k.parent}
}

func (k *SubKey) Revoked() bool {
	return C.subkey_revoked(k.k) != 0
}

func (k *SubKey) Expired() bool {
	return C.subkey_expired(k.k) != 0
}

func (k *SubKey) Disabled() bool {
	return C.subkey_disabled(k.k) != 0
}

func (k *SubKey) Invalid() bool {
	return C.subkey_invalid(k.k) != 0
}

func (k *SubKey) Secret() bool {
	return C.subkey_secret(k.k) != 0
}

func (k *SubKey) KeyID() string {
	return C.GoString(k.k.keyid)
}

func (k *SubKey) Fingerprint() string {
	return C.GoString(k.k.fpr)
}

func (k *SubKey) Created() time.Time {
	if k.k.timestamp <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(k.k.timestamp), 0)
}

func (k *SubKey) Expires() time.Time {
	if k.k.expires <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(k.k.expires), 0)
}

func (k *SubKey) CardNumber() string {
	return C.GoString(k.k.card_number)
}

// -- User ID --

type UserID struct {
	u      C.gpgme_user_id_t
	parent *Key // make sure the key is not released when we have a reference to a user ID
}

func (u *UserID) Next() *UserID {
	if u.u.next == nil {
		return nil /* this crashes in the calling function on assignment */
	}
	return &UserID{u: u.u.next, parent: u.parent}
}

func (u *UserID) HasNext() bool {
	return u.u.next != nil
}

func (u *UserID) Revoked() bool {
	return C.uid_revoked(u.u) != 0
}

func (u *UserID) Invalid() bool {
	return C.uid_invalid(u.u) != 0
}

func (u *UserID) Validity() Validity {
	return Validity(u.u.validity)
}

func (u *UserID) UID() string {
	return C.GoString(u.u.uid)
}

func (u *UserID) Name() string {
	return C.GoString(u.u.name)
}

func (u *UserID) Comment() string {
	return C.GoString(u.u.comment)
}

// Email returns the email address from the user id,
// when it was enclosed in <angel brackets>.
func (u *UserID) Email() string {
	return C.GoString(u.u.email)
}

// Returns the mail address even if it is without angel brackets.
func (u *UserID) Address() string {
	return C.GoString(u.u.address)
}

// -- UserID Signature --

// HasSig returns true if the user ID has at least one signature.
func (u *UserID) HasSig() bool {
	return u.u.signatures != nil
}

// A signature on a user ID.
// This structure shall be considered read-only and an application
// must not allocate such a structure on its own.
// The structure is defined in gpgme.h
type KeySig struct {
	ks     C.gpgme_key_sig_t // WARNING: Call Runtime.KeepAlive(ks) after ANY passing of k.k to C
	parent *Key              // make sure the key is not released when we have a reference to a user ID
}

// Signature returns the pointer to the first signature on the user ID.
func (u *UserID) Signatures() *KeySig {
	sigs := u.u.signatures
	runtime.KeepAlive(u)
	if sigs == nil {
		return nil
	}
	return &KeySig{ks: sigs, parent: u.parent} // The parent: k reference ensures sig remains valid
}

// HasNext returns true if there is another signature on the user ID.
func (s *KeySig) HasNext() bool {
	return s.ks.next != nil
}

// Next returns the next signature on the user ID.
func (s *KeySig) Next() *KeySig {
	if s.ks.next == nil {
		return nil
	}
	return &KeySig{ks: s.ks.next, parent: s.parent}
}

// Revoked returns true if the signature is revoked.
func (s *KeySig) Revoked() bool {
	return C.key_sig_revoked(s.ks) != 0
}

// Expired returns true if the signature is expired.
func (s *KeySig) Expired() bool {
	return C.key_sig_expired(s.ks) != 0
}

// Invalid returns true if the signature is invalid.
func (s *KeySig) Invalid() bool {
	return C.key_sig_invalid(s.ks) != 0
}

// Exportable returns true if the signature is exportable.
func (s *KeySig) Exportable() bool {
	return C.key_sig_exportable(s.ks) != 0
}

// KeyID returns the key ID of the signature.
func (s *KeySig) KeyID() string {
	return C.GoString(s.ks.keyid)
}

// Created returns the creation time of the signature.
func (s *KeySig) Created() time.Time {
	if s.ks.timestamp <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(s.ks.timestamp), 0)
}

// DoesExpire checks if an expiration time is set.
// If the signature does not expire, the function returns false.
// Internally, the a value of 0 for the expiration time
// is considered as "does not expire".
func (s *KeySig) DoesExpire() bool {
	return s.ks.expires != 0
}

// Expires returns the expiration time of the signature.
func (s *KeySig) Expires() time.Time {
	if s.ks.expires <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(s.ks.expires), 0)
}

// UID returns the user ID of the signature.
func (s *KeySig) UID() string {
	return C.GoString(s.ks.uid)
}

// Name returns the name of the signatures user ID.
func (s *KeySig) Name() string {
	return C.GoString(s.ks.name)
}

// Email returns the email address from the signatures user id.
func (s *KeySig) Email() string {
	return C.GoString(s.ks.email)
}

// Comment returns the comment of the signatures user ID.
func (s *KeySig) Comment() string {
	return C.GoString(s.ks.comment)
}

// TrustScope returns the trust scope of the trust signature.
// (the domain the trust signature is valid for)
func (s *KeySig) TrustScope() string {
	return C.GoString(s.ks.trust_scope)
}

// -- key signature notations --

// HasNotation returns true if the key signature has at least one notation.
func (s *KeySig) HasNotation() bool {
	return s.ks.notations != nil
}

// A notation on an user ID signature.
// This structure shall be considered read-only and an application
// must not allocate such a structure on its own.
// The structure is defined in gpgme.h
type Notation struct {
	sn     C.gpgme_sig_notation_t // WARNING: Call Runtime.KeepAlive(ns) after ANY passing of ks.ns to C
	parent *Key                   // make sure the key is not released when we have a reference to a user ID
}

// Signature returns the pointer to the first signature on the user ID.
func (s *KeySig) Notations() *Notation {
	notations := s.ks.notations
	runtime.KeepAlive(s)
	if notations == nil {
		return nil
	}
	return &Notation{sn: notations, parent: s.parent} // The parent: k reference ensures sig remains valid
}

// HasNext returns true if there is another signature on the user ID.
func (n *Notation) HasNext() bool {
	return n.sn.next != nil
}

// Next returns the next signature on the user ID.
func (n *Notation) Next() *Notation {
	if n.sn.next == nil {
		return nil
	}
	return &Notation{sn: n.sn.next, parent: n.parent}
}

// HumanReadable returns true if the notation is human readable.
func (n *Notation) HumanReadable() bool {
	return SignNotationFlags(n.sn.flags)&SignNotationHumanReadable != 0
}

// Critical returns true if the notation is critical.
func (n *Notation) Critical() bool {
	return SignNotationFlags(n.sn.flags)&SignNotationCritical != 0
}

// Name returns the name of the notation as a string, but only
// if the notation is marked as human readable.
// (It can still be garbage, because the human readable flag is not trustworthy)
func (n *Notation) Name() string {
	if !n.HumanReadable() || n.sn.name == nil || n.sn.name_len == 0 {
		return ""
	}
	return C.GoString(n.sn.name)
}

// Value returns the name of the notation as a string, but only
// if the notation is marked as human readable.
// (It can still be garbage, because the human readable flag is not trustworthy)
func (n *Notation) Value() string {
	if !n.HumanReadable() || n.sn.value == nil || n.sn.value_len == 0 {
		return ""
	}
	return C.GoString(n.sn.value)
}

// -- GPGME helper functions --

// AddressSpec returns the mail address (called “addr-spec” in RFC-5322) from
// the string *uid* which is assumed to be a user id (called “address” in
// RFC-5322).  All plain ASCII characters (i.e. those with bit 7 cleared) in
// the result are converted to lowercase.  Returns an empty string if no valid
// address was found
func AddrspecFromUid(uid string) string {
	cuid := C.CString(uid)
	defer C.free(unsafe.Pointer(cuid))
	// C: char * gpgme_addrspec_from_uid (const char *uid )
	mail := C.GoString(C.gpgme_addrspec_from_uid(cuid))
	return mail
}

// EOF
