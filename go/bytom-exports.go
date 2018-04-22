package main

//// formatter: off
import "C"
//// formatter: on

import (
	"fmt"
	"crypto/rand"
	"golang.org/x/crypto/nacl/box"
	//"golang.org/x/crypto/ripemd160"
	//"crypto/sha256"
	//"github.com/tendermint/go-crypto"
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

////export Ripemd126Hash
//func Ripemd126Hash(input []byte) (hash []byte) {
//	hasher := ripemd160.New()
//	hasher.Write(input)
//	hash = hasher.Sum(nil)
//	return
//}
//
////export Sha256Hash
//func Sha256Hash(input []byte) (hash []byte) {
//	hasher := sha256.New()
//	hasher.Write(input)
//	hash = hasher.Sum(nil)
//	return
//}
//
////export Ed25519GeneratePrivateKey
//func Ed25519GeneratePrivateKey() []byte {
//	return crypto.GenPrivKeyEd25519().Bytes()
//}
//
////export Ed25519PublicKey
//func Ed25519PublicKey(privateKeyBytes []byte) ([]byte, error) {
//	privateKey, err := crypto.PrivKeyFromBytes(privateKeyBytes)
//	if err != nil {
//		return nil, err
//	}
//	return privateKey.PubKey().Bytes(), nil
//}

func main() {
	fmt.Println("Hello go!")
}
