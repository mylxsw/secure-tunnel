//
//   date  : 2015-03-05
//   author: xjdrew
//

package tunnel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math/rand"
	"strings"
	"time"
)

const (
	TaaTokenSize     int = aes.BlockSize
	TaaSignatureSize int = md5.Size
	TaaBlockSize     int = TaaTokenSize + TaaSignatureSize
)

type authToken struct {
	challenge uint64
	timestamp uint64
}

func (t authToken) toBytes() []byte {
	buf := make([]byte, TaaTokenSize)
	binary.LittleEndian.PutUint64(buf, t.challenge)
	binary.LittleEndian.PutUint64(buf[8:], t.timestamp)
	return buf
}

func (t *authToken) fromBytes(buf []byte) {
	t.challenge = binary.LittleEndian.Uint64(buf)
	t.timestamp = binary.LittleEndian.Uint64(buf[8:])
}

// complement
func (t authToken) complement() authToken {
	return authToken{
		challenge: ^t.challenge,
		timestamp: ^t.timestamp,
	}
}

// isComplementary is complementary
func (t authToken) isComplementary(t1 authToken) bool {
	if t.challenge != ^t1.challenge || t.timestamp != ^t1.timestamp {
		return false
	}
	return true
}

// EncryptAlgorithm auth algorithm
type EncryptAlgorithm struct {
	block cipher.Block
	mac   hash.Hash
	token authToken
}

func NewEncryptAlgorithm(key string) *EncryptAlgorithm {
	token := sha256.Sum256([]byte(key))
	block, _ := aes.NewCipher(token[:TaaTokenSize])
	mac := hmac.New(md5.New, token[TaaTokenSize:])
	return &EncryptAlgorithm{
		block: block,
		mac:   mac,
	}
}

func init() {
	rand.Seed(time.Now().Unix())
}

// GenerateToken generate new token
func (a *EncryptAlgorithm) GenerateToken() {
	a.token.challenge = uint64(rand.Int63())
	a.token.timestamp = uint64(time.Now().UnixNano())
}

// GenerateCipherBlock generate cipher block
func (a *EncryptAlgorithm) GenerateCipherBlock(token *authToken) []byte {
	if token == nil {
		token = &a.token
	}

	dst := make([]byte, TaaBlockSize)
	a.block.Encrypt(dst, token.toBytes())
	a.mac.Write(dst[:TaaTokenSize])
	sign := a.mac.Sum(nil)
	a.mac.Reset()

	copy(dst[TaaTokenSize:], sign)
	return dst
}

func (a *EncryptAlgorithm) CheckSignature(src []byte) bool {
	a.mac.Write(src[:TaaTokenSize])
	expectedMac := a.mac.Sum(nil)
	a.mac.Reset()
	return hmac.Equal(src[TaaTokenSize:], expectedMac)
}

// ExchangeCipherBlock exchange cipher block
func (a *EncryptAlgorithm) ExchangeCipherBlock(src []byte) ([]byte, bool) {
	if len(src) != TaaBlockSize {
		return nil, false
	}

	if !a.CheckSignature(src) {
		return nil, false
	}

	dst := make([]byte, TaaTokenSize)
	a.block.Decrypt(dst, src)
	(&a.token).fromBytes(dst)

	// complement challenge
	token := a.token.complement()
	return a.GenerateCipherBlock(&token), true
}

// VerifyCipherBlock verify cipher block
func (a *EncryptAlgorithm) VerifyCipherBlock(src []byte) bool {
	if len(src) != TaaBlockSize {
		return false
	}

	if !a.CheckSignature(src) {
		return false
	}

	var token authToken
	dst := make([]byte, TaaTokenSize)
	a.block.Decrypt(dst, src)
	(&token).fromBytes(dst)
	return a.token.isComplementary(token)
}

func (a *EncryptAlgorithm) GetRc4key() []byte {
	return bytes.Repeat(a.token.toBytes(), 8)
}

func buildAuthPacket(username, password, backend string) []byte {
	return []byte(fmt.Sprintf("%s:%s@%s", username, password, backend))
}

func parseAuthPacket(data []byte) (username, password, backend string) {
	segs := strings.Split(string(data), "@")
	userInfos := strings.SplitN(strings.Join(segs[:len(segs)-1], "@"), ":", 2)

	backend = segs[len(segs)-1]
	username, password = userInfos[0], userInfos[1]
	return
}
