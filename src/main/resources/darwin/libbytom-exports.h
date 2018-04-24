/* Created by "go tool cgo" - DO NOT EDIT. */

/* package command-line-arguments */


#line 1 "cgo-builtin-prolog"

#include <stddef.h> /* for ptrdiff_t below */

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

typedef struct { const char *p; ptrdiff_t n; } _GoString_;

#endif

/* Start of preamble from import "C" comments.  */


#line 3 "/Users/freewind/go/src/github.com/freewind/bytom-exports-go-functions/go/bytom-exports.go"
// formatter: off

#line 1 "cgo-generated-wrapper"


/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef __SIZE_TYPE__ GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

typedef _GoString_ GoString;
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif


/* Return type for Curve25519GenerateKeyPair */
struct Curve25519GenerateKeyPair_return {
	void* r0; /* publicKeyPointer */
	GoInt r1; /* publicKeyLength */
	void* r2; /* privateKeyPointer */
	GoInt r3; /* privateKeyLength */
	char* r4; /* err */
};

extern struct Curve25519GenerateKeyPair_return Curve25519GenerateKeyPair();

/* Return type for Curve25519PreComputeSharedKey */
struct Curve25519PreComputeSharedKey_return {
	void* r0; /* sharedKey */
	GoInt r1; /* sharedKeyLength */
};

extern struct Curve25519PreComputeSharedKey_return Curve25519PreComputeSharedKey(void* p0, void* p1);

/* Return type for Ripemd160Hash */
struct Ripemd160Hash_return {
	void* r0; /* hash */
	GoInt r1; /* hashLength */
};

extern struct Ripemd160Hash_return Ripemd160Hash(void* p0, GoInt p1);

/* Return type for Sha256Hash */
struct Sha256Hash_return {
	void* r0; /* hash */
	GoInt r1; /* hashLength */
};

extern struct Sha256Hash_return Sha256Hash(void* p0, GoInt p1);

/* Return type for Ed25519GeneratePrivateKey */
struct Ed25519GeneratePrivateKey_return {
	void* r0; /* privateKey */
	GoInt r1; /* privateKeyLength */
};

extern struct Ed25519GeneratePrivateKey_return Ed25519GeneratePrivateKey();

/* Return type for Ed25519PublicKey */
struct Ed25519PublicKey_return {
	void* r0; /* publicKeyPointer */
	GoInt r1; /* publicKeyLength */
	char* r2; /* error */
};

extern struct Ed25519PublicKey_return Ed25519PublicKey(void* p0, GoInt p1);

/* Return type for Ed25519Sign */
struct Ed25519Sign_return {
	void* r0; /* signaturePointer */
	GoInt r1; /* signatureLength */
};

extern struct Ed25519Sign_return Ed25519Sign(void* p0, GoInt p1, void* p2, GoInt p3);

/* Return type for SecretboxSeal */
struct SecretboxSeal_return {
	void* r0; /* sealedPointer */
	GoInt r1; /* sealedLength */
};

extern struct SecretboxSeal_return SecretboxSeal(void* p0, GoInt p1, void* p2, GoInt p3, void* p4, GoInt p5);

/* Return type for SecretboxOpen */
struct SecretboxOpen_return {
	void* r0; /* messagePointer */
	GoInt r1; /* messageLength */
};

extern struct SecretboxOpen_return SecretboxOpen(void* p0, GoInt p1, void* p2, GoInt p3, void* p4, GoInt p5);

/* Return type for Wire_TwoByteArrays */
struct Wire_TwoByteArrays_return {
	void* r0; /* bytesPointer */
	GoInt r1; /* bytesLength */
};

extern struct Wire_TwoByteArrays_return Wire_TwoByteArrays(void* p0, GoInt p1, void* p2, GoInt p3);

/* Return type for Unwire_TwoByteArrays */
struct Unwire_TwoByteArrays_return {
	void* r0; /* arrayPointer1 */
	GoInt r1; /* arrayLength1 */
	void* r2; /* arrayPointer2 */
	GoInt r3; /* arrayLength2 */
};

extern struct Unwire_TwoByteArrays_return Unwire_TwoByteArrays(void* p0, GoInt p1);

extern GoUint8 Ed25519VerifySignature(void* p0, GoInt p1, void* p2, GoInt p3, void* p4, GoInt p5);

#ifdef __cplusplus
}
#endif
