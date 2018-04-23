package in.freewind.bytom.go_exports;

import com.sun.jna.Library;
import com.sun.jna.Pointer;
import in.freewind.bytom.go_exports.types.raw.*;

interface GoBytomRaw extends Library {

    RawKeyPairError Curve25519GenerateKeyPair();

    RawByteArray Curve25519PreComputeSharedKey(Pointer peerPublicKey, Pointer localPrivateKey);

    RawByteArray Ripemd160Hash(Pointer input, int inputLength);

    RawByteArray Sha256Hash(Pointer input, int inputLength);

    RawByteArray Ed25519GeneratePrivateKey();

    RawKeyError Ed25519PublicKey(Pointer privateKey, int privateKeyLength);

    RawByteArray Ed25519Sign(Pointer privateKeyPointer, int privateKeyLength, Pointer dataPointer, int dataPointerLength);

}
