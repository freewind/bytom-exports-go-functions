package in.freewind.bytom.go_exports;

import com.sun.jna.Library;
import com.sun.jna.Pointer;
import in.freewind.bytom.go_exports.types.raw.Curve25519GenerateKeyPair_RawReturn;
import in.freewind.bytom.go_exports.types.raw.Curve25519PreComputeSharedKey_RawReturn;

public interface GoBytomRaw extends Library {

    Curve25519GenerateKeyPair_RawReturn Curve25519GenerateKeyPair();

    Curve25519PreComputeSharedKey_RawReturn Curve25519PreComputeSharedKey(Pointer peerPublicKey, Pointer localPrivateKey);

}
