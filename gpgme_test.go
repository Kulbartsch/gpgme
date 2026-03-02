package gpgme

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testGPGHome    = "./testdata/gpghome"
	testData       = "data\n"
	testCipherText = `-----BEGIN PGP MESSAGE-----
Version: GnuPG v1

hQEMAw4698hF4WUhAQf/SdkbF/zUE6YjBxscDurrUZunSnt87kipLXypSxTDIdgj
O9huAaQwBz4uAJf2DuEN/7iAFGhi/v45NTujrG+7ocfjM3m/A2T80g4RVF5kKXBr
pFFgH7bMRY6VdZt1GKI9izSO/uFkoKXG8M31tCX3hWntQUJ9p+n1avGpu3wo4Ru3
CJhpL+ChDzXuZv4IK81ahrixEz4fJH0vd0TbsHpTXx4WPkTGXelM0R9PwiY7TovZ
onGZUIplrfA1HUUbQfzExyFw3oAo1/almzD5CBIfq5EnU8Siy5BNulDXm0/44h8A
lOUy6xqx7ITnWMYYf4a1cFoW80Yk+x6SYQqbcqHFQdJIAVr00V4pPV4ppFcXgdw/
BxKERzDupyqS0tcfVFCYLRmvtQp7ceOS6jRW3geXPPIz1U/VYBvKlvFu4XTMCS6z
4qY4SzZlFEsU
=IQOA
-----END PGP MESSAGE-----`
	textSignedCipherText = `-----BEGIN PGP MESSAGE-----
Version: GnuPG v1

hQEMAw4698hF4WUhAQf9FaI8zSltIMcDxqGtpcTfcBtC30rcKqE/oa1bacxuZQKW
uT671N7J2TjU8tLIsAO9lDSRHCsf6DbB+O6qOJsu6eJownyMUEmJ2oBON9Z2x+Ci
aS0KeRqcRxNJYbIth9/ffa2I4sSBA0GS93yCfGKHNL4JvNo/dgVjJwOPWZ5TKu49
n9h81LMwTQ8qpLGPeo7nsgBtSKNTi5s7pC0bd9HTii7gQcLUEeeqk5U7oG5CRN48
zKPrVud8pIDvSoYuymZmjWI1MmF4xQ+6IHK7hWKMyA2RkS4CpyBPERMifc+y+K2+
LnKLt2ul9jxgqv3fd/dU7UhyqdvJdj83tUvhN4Iru9LAuQHfVsP23keH8CHpUzCj
PkuUYvpgmRdMSC+l3yBCqnaaAI51rRdyJ+HX4DrrinOFst2JfXEICiQAg5UkO4i/
YYHsfD3xfk7MKMOY/DfV25OyAU6Yeq/5SMisONhtlzcosVU7HULudbIKSG6q/tCx
jRGu+oMIBdiQ+eipnaLVetyGxSEDzxHH367NbxC9ffxK7I+Srmwh+oS/yMNuZA8r
bUp6NbykK8Si7VNgVG1+yOIULLuR0VBO5+e2PKQU8FP0wABTn7h3zE8z4rCrcaZl
43bc/TBUyTdWY79e2P1otaCbhQGAjfF8ClPbAdsFppykf5I2ZDDf8c67d0Nqui74
Yry4/fF/2sAzyoyzdP6ktBw6pCA1MbwDqTGg7aEI8Es3X+jfh3qIaLnGmZ7jIyUl
D4jgGAEpFU+mpPH8eukKuT+OJ3P6gdmSiAJH7+C96tlcEg9BNxjYNkCTil/3yygQ
EV/5zFTEpzm4CtYHHdmY5uCaEJq/4hhE8BY8
=8mxI
-----END PGP MESSAGE-----`
	testSignedText = `-----BEGIN PGP MESSAGE-----
Version: GnuPG v1

owEBQwG8/pANAwACAQMn/7Ain2E2AcsTYgBW47+PVGVzdCBtZXNzYWdlCokBHAQA
AQIABgUCVuO/jwAKCRADJ/+wIp9hNh9lCACPiDkY0CqI9ss4EBcpToqnF/8NmV99
2wi6FmbQnUmY98OMM2VJXrX6PvfD/X+FsiLog0CZU4heMEAI3Dd3qELgTfaTFqNc
bbDkenzA0kO734WLsEU/z1F9iWAcfeF3crKqd3fBw5kZ1PkhuJFdcqQEOUQALvXY
8VAtQmQWzf3sn2KIQ7R1wyAJVoUZaN5Xwc9Y0F1l4Xxifax8nkFBl35X6gmHRxZ7
jlfmWMcAkXASNXl9/Yso2XGJMs85JPhZPJ3KJRuuurnhZSxAbDJMNBFJ+HbQv3y6
pupeR7ut6pWJxr6MND793yoFGoRYwKklQdfP4xzFCatYRU4RkPBp95KJ
=RMUj
-----END PGP MESSAGE-----
`
)

func TestMain(m *testing.M) {
	flag.Parse()
	os.Setenv("GNUPGHOME", absTestGPGHome())
	unsetenvGPGAgentInfo()
	os.Exit(m.Run())
}

func compareEngineInfo(t *testing.T, info *EngineInfo, proto Protocol, fileName, homeDir string) {
	for info != nil && info.Protocol() != proto {
		info = info.Next()
	}
	if info == nil {
		t.Errorf("Expected engine info %d not found", proto)
		return
	}
	if info.FileName() != fileName {
		t.Errorf("Testing file name %s does not match %s", info.FileName(), fileName)
	}
	if info.HomeDir() != homeDir {
		t.Errorf("Testing home directory %s does not match %s", info.HomeDir(), homeDir)
	}
}

func TestEngineInfo(t *testing.T) {
	testProto := ProtocolOpenPGP // Careful, this is global state!
	defer func() {
		_ = SetEngineInfo(testProto, "", "") // Try to reset to defaults after we are done.
	}()

	testFN := "testFN"
	testHomeDir := "testHomeDir"
	checkError(t, SetEngineInfo(testProto, testFN, testHomeDir))

	info, err := GetEngineInfo()
	checkError(t, err)
	compareEngineInfo(t, info, testProto, testFN, testHomeDir)

	// SetEngineInfo with empty strings works, using defaults which we don't know,
	// so just test that it doesn't fail.
	checkError(t, SetEngineInfo(testProto, testFN, ""))
	checkError(t, SetEngineInfo(testProto, "", testHomeDir))
}

func ctxWithCallback(t *testing.T) *Context {
	ctx, err := New()
	checkError(t, err)
	checkError(t, ctx.SetPinEntryMode(PinEntryLoopback))

	checkError(t, ctx.SetCallback(func(uid_hint string, prev_was_bad bool, f *os.File) error {
		if prev_was_bad {
			t.Fatal("Bad passphrase")
		}
		_, err := io.WriteString(f, "password\n")
		return err
	}))
	return ctx
}

func TestContext_Armor(t *testing.T) {
	ctx, err := New()
	checkError(t, err)

	ctx.SetArmor(true)
	if !ctx.Armor() {
		t.Error("expected armor set")
	}
	ctx.SetArmor(false)
	if ctx.Armor() {
		t.Error("expected armor not set")
	}
}

func TestContext_TextMode(t *testing.T) {
	ctx, err := New()
	checkError(t, err)

	ctx.SetTextMode(true)
	if !ctx.TextMode() {
		t.Error("expected textmode set")
	}
	ctx.SetTextMode(false)
	if ctx.TextMode() {
		t.Error("expected textmode not set")
	}
}

func TestContext_EngineInfo(t *testing.T) {
	ctx, err := New()
	checkError(t, err)

	testProto := ProtocolOpenPGP
	testFN := "testFN"
	testHomeDir := "testHomeDir"
	checkError(t, ctx.SetEngineInfo(testProto, testFN, testHomeDir))

	info := ctx.EngineInfo()
	compareEngineInfo(t, info, testProto, testFN, testHomeDir)

	// SetEngineInfo with empty strings works, using defaults which we don't know,
	// so just test that it doesn't fail.
	checkError(t, ctx.SetEngineInfo(testProto, testFN, ""))
	checkError(t, ctx.SetEngineInfo(testProto, "", testHomeDir))
}

func TestContext_Encrypt(t *testing.T) {
	ctx, err := New()
	checkError(t, err)

	keys, err := FindKeys("test@example.com", true)
	checkError(t, err)

	plain, err := NewDataBytes([]byte(testData))
	checkError(t, err)

	var buf bytes.Buffer
	cipher, err := NewDataWriter(&buf)
	checkError(t, err)

	checkError(t, ctx.Encrypt(keys, 0, plain, cipher))
	if buf.Len() < 1 {
		t.Error("Expected encrypted bytes, got empty buffer")
	}
}

func TestContext_Decrypt(t *testing.T) {
	ctx := ctxWithCallback(t)

	cipher, err := NewDataBytes([]byte(testCipherText))
	checkError(t, err)
	var buf bytes.Buffer
	plain, err := NewDataWriter(&buf)
	checkError(t, err)
	checkError(t, ctx.Decrypt(cipher, plain))
	diff(t, buf.Bytes(), []byte("Test message\n"))
}

func TestContext_DecryptVerify(t *testing.T) {
	ctx := ctxWithCallback(t)

	cipher, err := NewDataBytes([]byte(textSignedCipherText))
	checkError(t, err)
	var buf bytes.Buffer
	plain, err := NewDataWriter(&buf)
	checkError(t, err)
	checkError(t, ctx.DecryptVerify(cipher, plain))
	diff(t, buf.Bytes(), []byte("Test message\n"))
}

func TestContext_Sign(t *testing.T) {
	ctx := ctxWithCallback(t)

	key, err := ctx.GetKey("test@example.com", true)
	checkError(t, err)

	plain, err := NewDataBytes([]byte(testData))
	checkError(t, err)

	var buf bytes.Buffer
	signed, err := NewDataWriter(&buf)
	checkError(t, err)

	checkError(t, ctx.Sign([]*Key{key}, plain, signed, SigModeNormal))
	if buf.Len() < 1 {
		t.Error("Expected signed bytes, got empty buffer")
	}

	// Test SignResult
	signRes, err := ctx.SignResult()
	checkError(t, err)

	if len(signRes.InvalidSigners) != 0 {
		t.Errorf("Expected no invalid signers, got %d", len(signRes.InvalidSigners))
	}
	if len(signRes.Signatures) != 1 {
		t.Fatalf("Expected 1 new signature, got %d", len(signRes.Signatures))
	}

	newSig := signRes.Signatures[0]
	if newSig.Type != SigModeNormal {
		t.Errorf("Expected SigModeNormal, got %d", newSig.Type)
	}
	if newSig.Fingerprint == "" {
		t.Error("Expected non-empty fingerprint in sign result")
	}
	if newSig.Timestamp.IsZero() {
		t.Error("Expected non-zero timestamp in sign result")
	}
	t.Logf("SignResult: fingerprint=%s, algo=%s, hash=%s, class=%d",
		newSig.Fingerprint,
		PubkeyAlgoName(newSig.PubkeyAlgo),
		HashAlgoName(newSig.HashAlgo),
		newSig.SigClass)
}

func TestContext_SignResult(t *testing.T) {
	ctx, err := New()
	checkError(t, err)
	defer ctx.Release()

	checkError(t, ctx.SetPinEntryMode(PinEntryLoopback))
	checkError(t, ctx.SetCallback(func(uid_hint string, prev_was_bad bool, f *os.File) error {
		_, err := io.WriteString(f, "password\n")
		return err
	}))

	key, err := ctx.GetKey("test@example.com", true)
	checkError(t, err)

	plain, err := NewDataBytes([]byte(testData))
	checkError(t, err)

	var buf bytes.Buffer
	signed, err := NewDataWriter(&buf)
	checkError(t, err)

	checkError(t, ctx.Sign([]*Key{key}, plain, signed, SigModeDetach))

	signRes, err := ctx.SignResult()
	checkError(t, err)

	if len(signRes.InvalidSigners) != 0 {
		t.Errorf("Expected no invalid signers, got %d", len(signRes.InvalidSigners))
	}
	if len(signRes.Signatures) != 1 {
		t.Fatalf("Expected 1 new signature, got %d", len(signRes.Signatures))
	}

	newSig := signRes.Signatures[0]
	if newSig.Type != SigModeDetach {
		t.Errorf("Expected SigModeDetach (%d), got %d", SigModeDetach, newSig.Type)
	}
	if newSig.Fingerprint == "" {
		t.Error("Expected non-empty fingerprint in sign result")
	}
	if newSig.Timestamp.IsZero() {
		t.Error("Expected non-zero timestamp in sign result")
	}
	if PubkeyAlgoName(newSig.PubkeyAlgo) == "" {
		t.Error("Expected valid pubkey algorithm")
	}
	if HashAlgoName(newSig.HashAlgo) == "" {
		t.Error("Expected valid hash algorithm")
	}
	t.Logf("SignResult: fingerprint=%s, algo=%s, hash=%s, type=%d, class=%d",
		newSig.Fingerprint,
		PubkeyAlgoName(newSig.PubkeyAlgo),
		HashAlgoName(newSig.HashAlgo),
		newSig.Type,
		newSig.SigClass)
}

func TestContext_KeySign(t *testing.T) {
	ctx := ctxWithCallback(t)

	// key to sign
	sKey, err := ctx.GetKey("test2@example.com", false)
	checkError(t, err)
	uid := sKey.UserIDs()
	if uid == nil {
		t.Fatal("User ID 'test2@example.com' not found")
	}
	user := uid.UID()
	t.Logf("User ID to sign: '%s'", user)

	// signing key
	key, err := ctx.GetKey("test@example.com", true)
	checkError(t, err)
	err = ctx.SignersAdd(key)
	checkError(t, err)

	// sign
	err = ctx.KeySign(*sKey, user, time.Duration(time.Hour*24*730), 0)
	checkError(t, err)
}

func TestContext_Verify(t *testing.T) {
	ctx, err := New()
	checkError(t, err)

	_, err = ctx.GetKey("test@example.com", false)
	checkError(t, err)

	signed, err := NewDataBytes([]byte(testSignedText))
	checkError(t, err)

	var buf bytes.Buffer
	plain, err := NewDataWriter(&buf)
	checkError(t, err)

	_, sigs, err := ctx.Verify(signed, nil, plain)
	checkError(t, err)

	if len(sigs) != 1 {
		t.Error("Expected 1 signature")
	}
	sig := sigs[0]
	// Normalize
	expectedSig := Signature{
		Summary:        SigSumValid | SigSumGreen,
		Fingerprint:    "44B646DC347C31E867FF4F450327FFB0229F6136",
		Status:         nil,
		Notations:      sig.Notations,    // Ignore in comparison
		Timestamp:      sig.Timestamp,    // Ignore in comparison
		ExpTimestamp:   sig.ExpTimestamp, // Ignore in comparison
		WrongKeyUsage:  false,
		PKATrust:       0,
		ChainModel:     false,
		Validity:       ValidityFull,
		ValidityReason: nil,
		PubkeyAlgo:     sig.PubkeyAlgo, // Ignore in comparison
		HashAlgo:       sig.HashAlgo,   // Ignore in comparison
		PKAAddress:     sig.PKAAddress, // Ignore in comparison
		Key:            sig.Key,        // Ignore in comparison
	}
	if fmt.Sprintf("%#v", sig) != fmt.Sprintf("%#v", expectedSig) {
		t.Errorf("Signature verification does not match: %#v vs. %#v", sig, expectedSig)
	}

	diff(t, buf.Bytes(), []byte("Test message\n"))
}

func TestContext_Import(t *testing.T) {
	homeDir, err := ioutil.TempDir("", "gpgme-import-test")
	checkError(t, err)
	defer os.RemoveAll(homeDir)

	ctx, err := New()
	checkError(t, err)
	checkError(t, ctx.SetEngineInfo(ProtocolOpenPGP, "", homeDir))

	f, err := os.Open("./testdata/pubkeys.gpg")
	checkError(t, err)
	defer f.Close()
	dh, err := NewDataFile(f)
	checkError(t, err)
	defer dh.Close()

	res, err := ctx.Import(dh)
	checkError(t, err)

	for _, v := range []struct {
		Name     string
		Value    int
		Expected int
	}{
		{"Considered", res.Considered, 1},
		{"NoUserID", res.NoUserID, 0},
		{"Imported", res.Imported, 1},
		// Do not test ImportedRSA, as of gnupg 2.1.11 the value is always 0.
		{"Unchanged", res.Unchanged, 0},
		{"NewUserIDs", res.NewUserIDs, 0},
		{"NewSubKeys", res.NewSubKeys, 0},
		{"NewSignatures", res.NewSignatures, 0},
		{"NewRevocations", res.NewRevocations, 0},
		{"SecretRead", res.SecretRead, 0},
		{"SecretImported", res.SecretImported, 0},
		{"SecretUnchanged", res.SecretUnchanged, 0},
		{"NotImported", res.NotImported, 0},
	} {
		if v.Value != v.Expected {
			t.Errorf("Unexpected import result field %s, value %d, expected %d", v.Name, v.Value, v.Expected)
		}
	}
	expectedStatus := ImportStatus{
		Fingerprint: "44B646DC347C31E867FF4F450327FFB0229F6136",
		Result:      nil,
		Status:      ImportNew,
	}
	if len(res.Imports) != 1 {
		t.Errorf("Unexpected number of import status values %d", len(res.Imports))
	} else if res.Imports[0] != expectedStatus {
		t.Errorf("Import status does not match: %#v vs. %#v", res.Imports[0], expectedStatus)
	}
}

func TestContext_Export(t *testing.T) {
	ctx, err := New()
	checkError(t, err)

	data, err := NewData()
	checkError(t, err)

	err = ctx.Export("", 0, data)
	checkError(t, err)

	_, _ = data.Seek(0, 0)
	allKeys, err := ioutil.ReadAll(data)
	checkError(t, err)
	if len(allKeys) < 1 {
		t.Error("Expected exported keys, got empty buffer")
	}
}

func TestContext_CreateAndDeleteKey(t *testing.T) {
	ensureVersion(t, "2.", "CreateKey/DeleteKey test requires gpg 2.x")

	homeDir, err := ioutil.TempDir("", "gpgme-create-delete-test")
	checkError(t, err)
	defer os.RemoveAll(homeDir)

	ctx, err := New()
	checkError(t, err)
	defer ctx.Release()

	checkError(t, ctx.SetEngineInfo(ProtocolOpenPGP, "", homeDir))

	userID := fmt.Sprintf("create-delete-%d@example.com", time.Now().UnixNano())
	flags := CreateNoPasswd | CreateNoExpire
	checkError(t, ctx.CreateKey(userID, "default", 0, flags))

	key, err := ctx.GetKey(userID, true)
	checkError(t, err)
	if key == nil {
		t.Fatal("expected created key, got nil")
	}
	defer key.Release()

	sub := key.SubKeys()
	if sub == nil {
		t.Fatal("expected created key to have at least one subkey")
	}
	if sub.KeyLength() == 0 {
		t.Fatal("expected subkey key length > 0")
	}
	if PubkeyAlgoName(sub.Algo()) == "" {
		t.Fatalf("expected subkey algo to be known, got %d", sub.Algo())
	}

	checkError(t, ctx.DeleteKey(key, true, true))

	_, err = ctx.GetKey(userID, false)
	if err == nil {
		t.Fatal("expected key lookup error after deletion, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error after deletion, got: %v", err)
	}
}

func TestSubKey_Accessors(t *testing.T) {
	ctx, err := New()
	checkError(t, err)
	defer ctx.Release()

	key, err := ctx.GetKey("test@example.com", false)
	checkError(t, err)
	defer key.Release()

	sub := key.SubKeys()
	if sub == nil {
		t.Fatal("expected key to have at least one subkey")
	}
	if sub.KeyLength() == 0 {
		t.Fatal("expected subkey key length > 0")
	}
	if PubkeyAlgoName(sub.Algo()) == "" {
		t.Fatalf("expected subkey algo to be known, got %d", sub.Algo())
	}
	if fprV5 := sub.FingerprintV5(); fprV5 != "" && !isHexString(fprV5) {
		t.Fatalf("expected FingerprintV5 to be hex when set, got %q", fprV5)
	}
	if keygrip := sub.Keygrip(); keygrip != "" && !isHexString(keygrip) {
		t.Fatalf("expected Keygrip to be hex when set, got %q", keygrip)
	}
	if sub.IsCardKey() != sub.IsCardkey() {
		t.Fatalf("expected IsCardKey and IsCardkey to be equal: %t vs %t", sub.IsCardKey(), sub.IsCardkey())
	}
	if curve := sub.Curve(); (sub.Algo() == PubkeyAlgoECC || sub.Algo() == PubkeyAlgoECDSA || sub.Algo() == PubkeyAlgoECDH || sub.Algo() == PubkeyAlgoEDDSA) && curve == "" {
		t.Fatalf("expected non-empty curve name for ECC subkey algorithm %d", sub.Algo())
	}
}

func TestKeySig_Accessors(t *testing.T) {
	ctx, err := New()
	checkError(t, err)
	defer ctx.Release()
	checkError(t, ctx.SetKeyListMode(KeyListModeSigs))

	key, err := ctx.GetKey("test@example.com", false)
	checkError(t, err)
	defer key.Release()

	var sig *KeySig
	for uid := key.UserIDs(); uid != nil; uid = uid.Next() {
		sig = uid.Signatures()
		if sig != nil {
			break
		}
	}
	if sig == nil {
		t.Fatal("expected at least one user ID signature (with KeyListModeSigs)")
	}

	if PubkeyAlgoName(sig.PubkeyAlgo()) == "" {
		t.Fatalf("expected key signature pubkey algo to be known, got %d", sig.PubkeyAlgo())
	}
}

func TestGetDirInfo(t *testing.T) {
	dir := GetDirInfo("dirmngr-socket")
	if len(dir) < 1 {
		t.Error("Expected non-empty directory")
	} else {
		t.Log("GetDirInfo (dirmngr-socket): " + dir)
	}
	dir = GetDirInfo("")
	t.Log("GetDirInfo (empty): " + dir)
	if len(dir) != 0 {
		t.Error("Expected empty result")
	}
	dir = GetDirInfo("FooBar")
	t.Log("GetDirInfo (FooBar): " + dir)
	if len(dir) != 0 {
		t.Error("Expected empty result")
	}

}

func TestContext_AssuanSend(t *testing.T) {
	// Launch a gpg-agent in daemon mode
	cmd := exec.Command("gpg-connect-agent", "--verbose", "/bye")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		t.Skip(err)
	}

	ctx, err := New()
	checkError(t, err)
	err = ctx.SetProtocol(ProtocolAssuan)
	checkError(t, err)

	// NOP should simply succeed
	err = ctx.AssuanSend("NOP", nil, nil, nil)
	checkError(t, err)

	// GETINFO should return a version in Data
	var versionData []byte
	err = ctx.AssuanSend("GETINFO version",
		func(data []byte) error {
			versionData = data
			return nil
		},
		nil,
		nil,
	)
	checkError(t, err)
	if len(versionData) == 0 {
		t.Error("Expected version data")
	}

	err = ctx.AssuanSend("KILLAGENT", nil, nil, nil)
	checkError(t, err)
}

func TestAddrspecFromUid(t *testing.T) {
	for _, v := range []struct {
		uid      string
		expected string
	}{
		{"", ""},
		{"foo", ""},
		{"foo <foo@baa.com>", "foo@baa.com"},
		{"baa@foo.org", "baa@foo.org"},
	} {
		if v.expected != AddrspecFromUid(v.uid) {
			t.Errorf("Unexpected addrspec for %s: %s", v.uid, AddrspecFromUid(v.uid))
		}
	}
}

func isVersion(t testing.TB, version string) bool {
	t.Helper()
	var info *EngineInfo
	info, err := GetEngineInfo()
	checkError(t, err)
	for info != nil {
		if info.Protocol() == ProtocolOpenPGP {
			if strings.Contains(info.FileName(), "gpg") && strings.HasPrefix(info.Version(), version) {
				return true
			}
			return false
		}
		info = info.Next()
	}
	return false
}

var gpgBins = []string{"gpg2", "gpg1", "gpg"}

// ensureVersion tries to setup gpgme with a specific version or skip
func ensureVersion(t testing.TB, version, msg string) {
	t.Helper()
	if isVersion(t, version) {
		return
	}
	for _, bin := range gpgBins {
		path, err := exec.LookPath(bin)
		if err != nil {
			continue
		}
		if err := SetEngineInfo(ProtocolOpenPGP, path, absTestGPGHome()); err != nil {
			continue
		}
		if isVersion(t, version) {
			return
		}
	}
	t.Skip(msg)
}

func diff(t testing.TB, dst, src []byte) {
	t.Helper()
	line := 1
	offs := 0 // line offset
	for i := 0; i < len(dst) && i < len(src); i++ {
		d := dst[i]
		s := src[i]
		if d != s {
			t.Errorf("dst:%d: %s\n", line, dst[offs:i+1])
			t.Errorf("src:%d: %s\n", line, src[offs:i+1])
			return
		}
		if s == '\n' {
			line++
			offs = i + 1
		}
	}
	if len(dst) != len(src) {
		t.Errorf("len(dst) = %d, len(src) = %d\nsrc = %q", len(dst), len(src), src)
	}
}

func checkError(t testing.TB, err error) {
	t.Helper()
	if err == nil {
		return
	}
	t.Fatal(err)
}

func absTestGPGHome() string {
	f, err := filepath.Abs(testGPGHome)
	if err != nil {
		panic(err)
	}
	return f
}

func isHexString(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
