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
)

//export Curve25519GenerateKeyPair
func Curve25519GenerateKeyPair() (publicKey unsafe.Pointer, publicKeyLength int, privateKey unsafe.Pointer, privateKeyLength int, err *C.char) {
	tmpPublicKey, tmpPrivateKey, e := box.GenerateKey(rand.Reader)
	publicKey = C.CBytes(tmpPublicKey[:])
	publicKeyLength = len(tmpPublicKey)
	privateKey = C.CBytes(tmpPrivateKey[:])
	privateKeyLength = len(tmpPrivateKey)
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
	copy(fixedPeerPublicKey[:], C.GoBytes(peerPublicKey, 32))
	copy(fixedLocalPrivateKey[:], C.GoBytes(localPrivateKey, 32))
	box.Precompute(sharedKeyBytes, &fixedPeerPublicKey, &fixedLocalPrivateKey)
	sharedKey = C.CBytes(sharedKeyBytes[:])
	sharedKeyLength = len(sharedKeyBytes)
	return
}

//export Ripemd160Hash
func Ripemd160Hash(input unsafe.Pointer, inputLength int) (hash unsafe.Pointer, hashLength int) {
	hasher := ripemd160.New()
	hasher.Write(C.GoBytes(input, C.int(inputLength)))
	result := hasher.Sum(nil)
	hash = C.CBytes(result)
	hashLength = len(result)
	return
}

//export Sha256Hash
func Sha256Hash(input unsafe.Pointer, inputLength int) (hash unsafe.Pointer, hashLength int) {
	hasher := sha256.New()
	hasher.Write(C.GoBytes(input, C.int(inputLength)))
	result := hasher.Sum(nil)
	hash = C.CBytes(result)
	hashLength = len(result)
	return
}

//export Ed25519GeneratePrivateKey
func Ed25519GeneratePrivateKey() (privateKey unsafe.Pointer, privateKeyLength int) {
	key := crypto.GenPrivKeyEd25519().Bytes()
	privateKey = C.CBytes(key)
	privateKeyLength = len(key)
	return
}

//export Ed25519PublicKey
func Ed25519PublicKey(privateKey unsafe.Pointer, privateKeyLength int) (publicKey unsafe.Pointer, publicKeyLength int, error *C.char) {
	privateKeyBytes := C.GoBytes(privateKey, C.int(privateKeyLength))
	priKey, err := crypto.PrivKeyFromBytes(privateKeyBytes)
	if err != nil {
		return nil, 0, C.CString(err.Error())
	}
	pubKey := priKey.PubKey().Bytes()
	publicKey = C.CBytes(pubKey)
	publicKeyLength = len(pubKey)
	return
}

// required
func main() {
}
