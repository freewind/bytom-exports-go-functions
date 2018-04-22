package in.freewind.bytom.go_exports;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import in.freewind.bytom.go_exports.types.Curve25519GenerateKeyPair_Return;
import in.freewind.bytom.go_exports.types.raw.Curve25519GenerateKeyPair_RawReturn;
import in.freewind.bytom.go_exports.types.raw.Curve25519PreComputeSharedKey_RawReturn;

public class GoBytom {
    private final GoBytomRaw raw;

    public GoBytom(GoBytomRaw raw) {
        this.raw = raw;
    }

    public Curve25519GenerateKeyPair_Return curve25519GenerateKeyPair() {
        Curve25519GenerateKeyPair_RawReturn rawResult = raw.Curve25519GenerateKeyPair();
        Curve25519GenerateKeyPair_Return result = new Curve25519GenerateKeyPair_Return();
        result.publicKey = rawResult.r0.getByteArray(0, rawResult.r1);
        System.out.println("r1: " + rawResult.r1);
        result.privateKey = rawResult.r2.getByteArray(0, rawResult.r3);
        System.out.println("r3: " + rawResult.r3);
        result.error = rawResult.r4;
        return result;
    }

    public byte[] curve25519PreComputeSharedKey(byte[] peerPublicKey, byte[] localPrivateKey) {
        Curve25519PreComputeSharedKey_RawReturn rawResult = raw.Curve25519PreComputeSharedKey(createPointer(peerPublicKey), createPointer(localPrivateKey));
        System.out.println("r1: " + rawResult.r1);
        return rawResult.r0.getByteArray(0, rawResult.r1);
    }

    private static Pointer createPointer(byte[] data) {
        Pointer pointer = new Memory(data.length + 1);
        pointer.write(0, data, 0, data.length);
        pointer.setByte(data.length, (byte) 0);
        return pointer;
    }

}
