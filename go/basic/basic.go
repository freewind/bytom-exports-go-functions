package basic

import "C"
import "unsafe"

func ToSlice(pointer unsafe.Pointer, length int) []byte {
	return C.GoBytes(pointer, C.int(length))
}

func ToPointer(bytes []byte) (unsafe.Pointer, int) {
	return C.CBytes(bytes), len(bytes)
}

func ToByte32(pointer unsafe.Pointer, length int) [32]byte {
	var key [32]byte
	copy(key[:], ToSlice(pointer, length))
	return key
}

func ToByte24(pointer unsafe.Pointer, length int) [24]byte {
	var byte24 [24]byte
	copy(byte24[:], ToSlice(pointer, length))
	return byte24
}

