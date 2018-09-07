package secp256k1

// #include "c-secp256k1/include/secp256k1.h"
// #cgo LDFLAGS: ${SRCDIR}/c-secp256k1/.libs/libsecp256k1.a
import "C"
import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

var (
	sCtx *C.secp256k1_context = nil
	vCtx *C.secp256k1_context = nil

	sInit sync.Once
	vInit sync.Once
)

func signCtx() *C.secp256k1_context {
	sInit.Do(func() {
		sCtx = C.secp256k1_context_create(C.SECP256K1_CONTEXT_SIGN)
		contextRandomize(sCtx)
	})
	return sCtx
}

func verifyCtx() *C.secp256k1_context {
	vInit.Do(func() {
		vCtx = C.secp256k1_context_create(C.SECP256K1_CONTEXT_VERIFY)
	})
	return vCtx
}

func contextRandomize(ctx *C.secp256k1_context) error {
	buf := make([]byte, 32)
	n, err := rand.Read(buf)
	if err != nil {
		return err
	} else if n != 32 {
		return errors.New("secp256k1_context_randomize: generated seed length is not 32 bytes")
	}
	ok := int(C.secp256k1_context_randomize(ctx, cBuf(buf)))
	if ok == 0 {
		return errors.New("secp256k1_context_randomize update randomizationfailed")
	}
	return nil
}

// secp256k1 private key
type PrivateKey struct {
	key []byte
}

// secp256k1 public key
type PublicKey struct {
	key *C.secp256k1_pubkey
}

func (p *PrivateKey) Public() *PublicKey {
	ctx := signCtx()
	pub := &PublicKey{key: &C.secp256k1_pubkey{}}
	if int(C.secp256k1_ec_pubkey_create(ctx, pub.key, cBuf(p.key))) != 1 {
		return nil
	}
	return pub
}

func (p *PrivateKey) Serialize() []byte {
	return append([]byte(nil), p.key...)
}

func (p *PrivateKey) Parse(data []byte) error {
	if size := len(data); size != 32 {
		return fmt.Errorf("invalid private key length: %d", size)
	}
	p.key = append([]byte(nil), data...)
	return nil
}

func (p *PublicKey) Serialize() []byte {
	ctx := verifyCtx()
	out := make([]byte, 33)
	outlen := C.size_t(33)
	C.secp256k1_ec_pubkey_serialize(ctx, cBuf(out), &outlen, p.key, C.SECP256K1_EC_COMPRESSED)
	return out
}

func (p *PublicKey) Parse(data []byte) error {
	ctx := verifyCtx()
	if p.key == nil {
		p.key = &C.secp256k1_pubkey{}
	}
	ok := int(C.secp256k1_ec_pubkey_parse(ctx, p.key, cBuf(data), C.size_t(len(data))))
	if ok != 1 {
		return errors.New("parse secp256k1 public key failed")
	}
	return nil
}

func GenerateKeyPair() (*PrivateKey, *PublicKey, error) {
	for {
		var buf [32]byte
		_, err := rand.Read(buf[:])
		if err != nil {
			return nil, nil, err
		}
		pri := &PrivateKey{buf[:]}
		return pri, pri.Public(), nil
	}
}

// Sign create a ECDSA signature to the 32-byte hash with the private key
// The output signature data is a 64-byte slice
func Sign(key *PrivateKey, hash []byte) ([]byte, error) {
	ctx := signCtx()
	sig := &C.secp256k1_ecdsa_signature{}
	res := int(C.secp256k1_ecdsa_sign(ctx, sig, cBuf(hash), cBuf(key.key), nil, nil))
	if res != 1 {
		return nil, errors.New("secp256k1_ecdsa_sign failed")
	}

	var buf [64]byte
	C.secp256k1_ecdsa_signature_serialize_compact(ctx, cBuf(buf[:]), sig)
	return buf[:], nil
}

// Verify a ECDSA signature.
// The input hash should be 32 bytes and signature data should be 64 bytes
func Verify(key *PublicKey, hash, sig []byte) bool {
	ctx := verifyCtx()
	buf := &C.secp256k1_ecdsa_signature{}
	if int(C.secp256k1_ecdsa_signature_parse_compact(ctx, buf, cBuf(sig))) != 1 {
		return false
	}
	ok := int(C.secp256k1_ecdsa_verify(ctx, buf, cBuf(hash), key.key))
	return ok == 1
}

func cBuf(goSlice []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&goSlice[0]))
}

func goBytes(cSlice []C.uchar, size C.int) []byte {
	return C.GoBytes(unsafe.Pointer(&cSlice[0]), size)
}
