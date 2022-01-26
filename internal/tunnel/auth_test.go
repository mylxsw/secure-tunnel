//
//   date  : 2015-03-06
//   author: xjdrew
//

package tunnel

import "testing"

func TestAuth(t *testing.T) {
	key := "a test key"
	a1 := newEncryptAlgorithm(key)
	a2 := newEncryptAlgorithm(key)

	a1.generateToken()
	b1 := a1.generateCipherBlock(nil)
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
