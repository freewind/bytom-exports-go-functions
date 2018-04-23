package in.freewind.bytom.go_exports;

import com.sun.jna.Library;
import com.sun.jna.Pointer;
import in.freewind.bytom.go_exports.types.raw.*;

interface GoBytomRaw extends Library {

    RawKeyPairError Curve25519GenerateKeyPair();

    RawKey Curve25519PreComputeSharedKey(Pointer peerPublicKey, Pointer localPrivateKey);

    RawKey Ripemd160Hash(Pointer input, int inputLength);

    RawKey Sha256Hash(Pointer input, int inputLength);

    RawKey Ed25519GeneratePrivateKey();

    RawKeyError Ed25519PublicKey(Pointer privateKey, int privateKeyLength);

}
