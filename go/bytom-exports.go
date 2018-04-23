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
	"unsafe"
	"github.com/tendermint/ed25519"
	"golang.org/x/crypto/nacl/secretbox"
)

//export Curve25519GenerateKeyPair
func Curve25519GenerateKeyPair() (publicKeyPointer unsafe.Pointer, publicKeyLength int, privateKeyPointer unsafe.Pointer, privateKeyLength int, err *C.char) {
	tmpPublicKey, tmpPrivateKey, e := box.GenerateKey(rand.Reader)
	publicKeyPointer, publicKeyLength = toPointer(tmpPublicKey[:])
	privateKeyPointer, privateKeyLength = toPointer(tmpPrivateKey[:])
	if e == nil {
		err = nil
	} else {
		err = C.CString(e.Error())
	}
	return
}

//export Curve25519PreComputeSharedKey
func Curve25519PreComputeSharedKey(peerPublicKey unsafe.Pointer, localPrivateKey unsafe.Pointer) (sharedKey unsafe.Pointer, sharedKeyLength int) {
	sharedKeyBytes := new([32]byte)
	var fixedPeerPublicKey, fixedLocalPrivateKey [32]byte
	copy(fixedPeerPublicKey[:], toBytes(peerPublicKey, 32))
	copy(fixedLocalPrivateKey[:], toBytes(localPrivateKey, 32))
	box.Precompute(sharedKeyBytes, &fixedPeerPublicKey, &fixedLocalPrivateKey)
	return toPointer(sharedKeyBytes[:])
}

//export Ripemd160Hash
func Ripemd160Hash(input unsafe.Pointer, inputLength int) (hash unsafe.Pointer, hashLength int) {
	hasher := ripemd160.New()
	hasher.Write(toBytes(input, inputLength))
	result := hasher.Sum(nil)
	return toPointer(result)
}

//export Sha256Hash
func Sha256Hash(input unsafe.Pointer, inputLength int) (hash unsafe.Pointer, hashLength int) {
	hasher := sha256.New()
	hasher.Write(toBytes(input, inputLength))
	result := hasher.Sum(nil)
	return toPointer(result)
}

//export Ed25519GeneratePrivateKey
func Ed25519GeneratePrivateKey() (privateKey unsafe.Pointer, privateKeyLength int) {
	return toPointer(crypto.GenPrivKeyEd25519().Bytes())
}

//export Ed25519PublicKey
func Ed25519PublicKey(privateKeyPointer unsafe.Pointer, privateKeyLength int) (publicKeyPointer unsafe.Pointer, publicKeyLength int, error *C.char) {
	privateKeyBytes := toBytes(privateKeyPointer, privateKeyLength)
	priKey, err := crypto.PrivKeyFromBytes(privateKeyBytes)
	if err != nil {
		return nil, 0, C.CString(err.Error())
	}
	pubKey := priKey.PubKey().Bytes()
	publicKeyPointer, publicKeyLength = toPointer(pubKey)
	return
}

//export Ed25519Sign
func Ed25519Sign(privateKeyPointer unsafe.Pointer, privateKeyLength int, dataPointer unsafe.Pointer, dataLength int) (signaturePointer unsafe.Pointer, signatureLength int) {
	var privateKey [64]byte
	copy(privateKey[:], toBytes(privateKeyPointer, privateKeyLength))
	data := toBytes(dataPointer, dataLength)
	signature := ed25519.Sign(&privateKey, data)
	return toPointer(signature[:])
}

func toBytes(pointer unsafe.Pointer, length int) []byte {
	return C.GoBytes(pointer, C.int(length))
}

//export SecretboxSeal
func SecretboxSeal(messagePointer unsafe.Pointer, messageLength int, noncePointer unsafe.Pointer, nonceLength int, keyPointer unsafe.Pointer, keyLength int) (sealedPointer unsafe.Pointer, sealedLength int) {
	var nonce [24]byte
	var key [32]byte
	copy(nonce[:], toBytes(noncePointer, nonceLength))
	copy(key[:], toBytes(keyPointer, keyLength))
	sealed := secretbox.Seal([]byte{}, toBytes(messagePointer, messageLength), &nonce, &key)
	return toPointer(sealed)
}

//export SecretboxOpen
func SecretboxOpen(boxPointer unsafe.Pointer, boxLength int, noncePointer unsafe.Pointer, nonceLength int, keyPointer unsafe.Pointer, keyLength int) (messagePointer unsafe.Pointer, messageLength int) {
	var nonce [24]byte
	var key [32]byte
	copy(nonce[:], toBytes(noncePointer, nonceLength))
	copy(key[:], toBytes(keyPointer, keyLength))
	message, ok := secretbox.Open([]byte{}, toBytes(boxPointer, boxLength), &nonce, &key)
	if ok {
		return toPointer(message)
	} else {
		return nil, 0
	}
}

func toPointer(bytes []byte) (unsafe.Pointer, int) {
	return C.CBytes(bytes), len(bytes)
}

// required
func main() {
}
