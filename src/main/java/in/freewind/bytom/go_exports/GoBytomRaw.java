package in.freewind.bytom.go_exports;

import com.sun.jna.Library;
import com.sun.jna.Pointer;
import in.freewind.bytom.go_exports.types.raw.*;

interface GoBytomRaw extends Library {

    RawKeyPairError Curve25519GenerateKeyPair();

    RawByteArray Curve25519PreComputeSharedKey(Pointer peerPublicKey, int peerPublicKeyLength, Pointer localPrivateKey, int localPrivateKeyLength);

    RawByteArray Ripemd160Hash(Pointer input, int inputLength);

    RawByteArray Sha256Hash(Pointer input, int inputLength);

    RawByteArray Ed25519GeneratePrivateKey();

    RawByteArray Ed25519PublicKey(Pointer privateKey, int privateKeyLength);

    RawByteArray Ed25519Sign(Pointer privateKeyPointer, int privateKeyLength, Pointer dataPointer, int dataPointerLength);

    RawByteArray SecretboxSeal(Pointer messagePointer, int messageLength, Pointer noncePointer, int nonceLength, Pointer keyPointer, int keyLength);

    RawByteArray SecretboxOpen(Pointer boxPointer, int boxLength, Pointer noncePointer, int nonceLength, Pointer keyPointer, int keyLength);

    RawByteArray Wire_OneByteArray(Pointer arrayPointer1, int arrayLength1);

    RawByteArray Unwire_OneByteArray(Pointer arrayPointer1, int arrayLength1);

    RawByteArray Wire_AuthSigMessage(Pointer publicKeyPointer, int publicKeyLength, Pointer signaturePointer, int signatureLength);

    RawAuthSigMessage Unwire_AuthSigMessage(Pointer dataPointer, int dataLength);

    boolean Ed25519VerifySignature(Pointer publicKeyPointer, int publicKeyLength, Pointer messagePointer, int messageLength, Pointer signaturePointer, int signatureLength);

}
