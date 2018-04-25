package main

//// formatter: off
import "C"
//// formatter: on

import (
	"crypto/rand"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/ripemd160"
	"crypto/sha256"
	"github.com/tendermint/go-crypto"
	"github.com/tendermint/go-wire"
	"unsafe"
	"golang.org/x/crypto/nacl/secretbox"
	"github.com/freewind/bytom-exports-go-functions/go/ed25519"
	"github.com/freewind/bytom-exports-go-functions/go/basic"
)

//export Curve25519GenerateKeyPair
func Curve25519GenerateKeyPair() (publicKeyPointer unsafe.Pointer, publicKeyLength int, privateKeyPointer unsafe.Pointer, privateKeyLength int, err *C.char) {
	tmpPublicKey, tmpPrivateKey, e := box.GenerateKey(rand.Reader)
	publicKeyPointer, publicKeyLength = basic.ToPointer(tmpPublicKey[:])
	privateKeyPointer, privateKeyLength = basic.ToPointer(tmpPrivateKey[:])
	if e == nil {
		err = nil
	} else {
		err = C.CString(e.Error())
	}
	return
}

//export Curve25519PreComputeSharedKey
func Curve25519PreComputeSharedKey(peerPublicKeyPointer unsafe.Pointer, pLength int, localPrivateKeyPointer unsafe.Pointer, lLength int) (sharedKey unsafe.Pointer, sharedKeyLength int) {
	peerPublicKey := basic.ToByte32(peerPublicKeyPointer, pLength)
	localPrivateKey := basic.ToByte32(localPrivateKeyPointer, lLength)
	sharedKeyBytes := new([32]byte)
	box.Precompute(sharedKeyBytes, &peerPublicKey, &localPrivateKey)
	return basic.ToPointer(sharedKeyBytes[:])
}

//export Ripemd160Hash
func Ripemd160Hash(input unsafe.Pointer, inputLength int) (hash unsafe.Pointer, hashLength int) {
	hasher := ripemd160.New()
	hasher.Write(basic.ToSlice(input, inputLength))
	result := hasher.Sum(nil)
	return basic.ToPointer(result)
}

//export Sha256Hash
func Sha256Hash(input unsafe.Pointer, inputLength int) (hash unsafe.Pointer, hashLength int) {
	hasher := sha256.New()
	hasher.Write(basic.ToSlice(input, inputLength))
	result := hasher.Sum(nil)
	return basic.ToPointer(result)
}

//export Ed25519GeneratePrivateKey
func Ed25519GeneratePrivateKey() (keyPointer unsafe.Pointer, keyLength int) {
	privateKey := crypto.GenPrivKeyEd25519()
	return ed25519.PrivateKeyToPointer(privateKey)
}

//export Ed25519PublicKey
func Ed25519PublicKey(privateKeyPointer unsafe.Pointer, privateKeyLength int) (publicKeyPointer unsafe.Pointer, publicKeyLength int) {
	priKey := ed25519.ToPrivateKey(privateKeyPointer, privateKeyLength)
	pubKey := priKey.PubKey()
	return ed25519.PublicKeyToPointer(pubKey)
}

//export Ed25519Sign
func Ed25519Sign(privateKeyPointer unsafe.Pointer, privateKeyLength int, dataPointer unsafe.Pointer, dataLength int) (signaturePointer unsafe.Pointer, signatureLength int) {
	privateKey := ed25519.ToPrivateKey(privateKeyPointer, privateKeyLength)
	data := basic.ToSlice(dataPointer, dataLength)
	signature := privateKey.Sign(data)
	return ed25519.SignatureToPointer(signature)
}

//export SecretboxSeal
func SecretboxSeal(messagePointer unsafe.Pointer, messageLength int, noncePointer unsafe.Pointer, nonceLength int, keyPointer unsafe.Pointer, keyLength int) (sealedPointer unsafe.Pointer, sealedLength int) {
	nonce := basic.ToByte24(noncePointer, nonceLength)
	key := basic.ToByte32(keyPointer, keyLength)
	message := basic.ToSlice(messagePointer, messageLength)
	sealedMessage := secretbox.Seal([]byte{}, message, &nonce, &key)
	return basic.ToPointer(sealedMessage)
}

//export SecretboxOpen
func SecretboxOpen(boxPointer unsafe.Pointer, boxLength int, noncePointer unsafe.Pointer, nonceLength int, keyPointer unsafe.Pointer, keyLength int) (messagePointer unsafe.Pointer, messageLength int) {
	nonce := basic.ToByte24(noncePointer, nonceLength)
	key := basic.ToByte32(keyPointer, keyLength)
	sealedMessage := basic.ToSlice(boxPointer, boxLength)
	message, ok := secretbox.Open([]byte{}, sealedMessage, &nonce, &key)
	if ok {
		return basic.ToPointer(message)
	} else {
		return nil, 0
	}
}

//export Wire_OneByteArray
func Wire_OneByteArray(arrayPointer1 unsafe.Pointer, arrayLength1 int) (bytesPointer unsafe.Pointer, bytesLength int) {
	bytes := wire.BinaryBytes(oneByteArray{
		Array: basic.ToSlice(arrayPointer1, arrayLength1),
	})
	return basic.ToPointer(bytes)
}

//export Unwire_OneByteArray
func Unwire_OneByteArray(dataPointer unsafe.Pointer, dataLength int) (arrayPointer1 unsafe.Pointer, arrayLength1 int) {
	data := basic.ToSlice(dataPointer, dataLength)
	obj := oneByteArray{}
	wire.ReadBinaryBytes(data, &obj)
	return basic.ToPointer(obj.Array)
}

//export Wire_AuthSigMessage
func Wire_AuthSigMessage(publicKeyPointer unsafe.Pointer, publicKeyLength int, signaturePointer unsafe.Pointer, signatureLength int) (messagePointer unsafe.Pointer, messageLength int) {
	bytes := wire.BinaryBytes(authSigMessage{
		Key: ed25519.ToPublicKey(publicKeyPointer, publicKeyLength).Wrap(),
		Sig: ed25519.ToSignature(signaturePointer, signatureLength).Wrap(),
	})
	return basic.ToPointer(bytes)
}

//export Unwire_AuthSigMessage
func Unwire_AuthSigMessage(dataPointer unsafe.Pointer, dataLength int) (arrayPointer1 unsafe.Pointer, arrayLength1 int, arrayPointer2 unsafe.Pointer, arrayLength2 int) {
	data := basic.ToSlice(dataPointer, dataLength)
	obj := authSigMessage{}
	wire.ReadBinaryBytes(data, &obj)
	arrayPointer1, arrayLength1 = ed25519.PublicKeyToPointer(obj.Key)
	arrayPointer2, arrayLength2 = ed25519.SignatureToPointer(obj.Sig)
	return
}

//export Ed25519VerifySignature
func Ed25519VerifySignature(publicKeyPointer unsafe.Pointer, publicKeyLength int, messagePointer unsafe.Pointer, messageLength int, signaturePointer unsafe.Pointer, signatureLength int) bool {
	publicKey := ed25519.ToPublicKey(publicKeyPointer, publicKeyLength)
	signature := ed25519.ToSignature(signaturePointer, signatureLength)
	message := basic.ToSlice(messagePointer, messageLength)
	return publicKey.VerifyBytes(message, signature.Wrap())
}

type oneByteArray struct {
	Array []byte
}

type authSigMessage struct {
	Key crypto.PubKey
	Sig crypto.Signature
}

// required
func main() {
}
