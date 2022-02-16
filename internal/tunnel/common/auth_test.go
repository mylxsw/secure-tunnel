package common

import "testing"

func TestAuth(t *testing.T) {
	key := "a test key"
	a1 := NewEncryptAlgorithm(key)
	a2 := NewEncryptAlgorithm(key)

	a1.GenerateToken()
	b1 := a1.GenerateCipherBlock(nil)
	t.Log("block 1:", b1)
	if !a1.CheckSignature(b1) {
		t.Fatal("check signature failed")
	}

	b2, ok := a2.ExchangeCipherBlock(b1)
	t.Log("block 2:", b2)
	if !ok {
		t.Fatal("exchange block failed")
	}

	if !a1.VerifyCipherBlock(b2) {
		t.Fatal("verify exchanged block failed")
	}
}
