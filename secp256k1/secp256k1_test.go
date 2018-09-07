package secp256k1

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestGenerate(t *testing.T) {
	pri, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("private key:", hex.EncodeToString(pri.Serialize()))
	t.Log("public key:", hex.EncodeToString(pub.Serialize()))

	msg := []byte("abcd")
	hash := sha256.Sum256(msg)
	sig, err := Sign(pri, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	t.Log("signature:", hex.EncodeToString(sig))
	if !Verify(pub, hash[:], sig) {
		t.Fatal("verify failed")
	}
}
