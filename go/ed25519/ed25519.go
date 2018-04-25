package ed25519

import "C"
import (
	"unsafe"
	"github.com/tendermint/go-crypto"
	"github.com/freewind/bytom-exports-go-functions/go/basic"
)

func ToPrivateKey(privateKeyPointer unsafe.Pointer, privateKeyLength int) crypto.PrivKeyEd25519 {
	var privateKey [64]byte
	privateKeySlice := basic.ToSlice(privateKeyPointer, privateKeyLength)
	copy(privateKey[:], privateKeySlice)
	return crypto.PrivKeyEd25519(privateKey)
}

func PrivateKeyToPointer(key crypto.PrivKeyEd25519) (unsafe.Pointer, int) {
	bytes := [64]byte(key)
	return basic.ToPointer(bytes[:])
}

func PublicKeyToPointer(key crypto.PubKey) (unsafe.Pointer, int) {
	bytes := [32]byte(key.Unwrap().(crypto.PubKeyEd25519))
	return basic.ToPointer(bytes[:])
}

func SignatureToPointer(signature crypto.Signature) (unsafe.Pointer, int) {
	bytes := [64]byte(signature.Unwrap().(crypto.SignatureEd25519))
	return basic.ToPointer(bytes[:])
}

func ToSignature(dataPointer unsafe.Pointer, dataLength int) crypto.SignatureEd25519 {
	var bytes [64]byte
	copy(bytes[:], basic.ToSlice(dataPointer, dataLength))
	return crypto.SignatureEd25519(bytes)
}

func ToPublicKey(publicKeyPointer unsafe.Pointer, publicKeyLength int) crypto.PubKeyEd25519 {
	var publicKeyBytes [32]byte
	copy(publicKeyBytes[:], basic.ToSlice(publicKeyPointer, publicKeyLength))
	return crypto.PubKeyEd25519(publicKeyBytes)
}
