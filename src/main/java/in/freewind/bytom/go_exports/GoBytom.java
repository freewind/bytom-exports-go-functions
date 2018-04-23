package in.freewind.bytom.go_exports;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import in.freewind.bytom.go_exports.types.KeyError;
import in.freewind.bytom.go_exports.types.KeyPairError;
import in.freewind.bytom.go_exports.types.raw.RawKey;
import in.freewind.bytom.go_exports.types.raw.RawKeyError;
import in.freewind.bytom.go_exports.types.raw.RawKeyPairError;

public class GoBytom {
    private final GoBytomRaw raw;

    private GoBytom(GoBytomRaw raw) {
        this.raw = raw;
    }

    public KeyPairError curve25519GenerateKeyPair() {
        RawKeyPairError rawResult = raw.Curve25519GenerateKeyPair();
        byte[] publicKey = rawResult.r0.getByteArray(0, rawResult.r1);
        byte[] privateKey = rawResult.r2.getByteArray(0, rawResult.r3);
        String error = rawResult.r4;
        return new KeyPairError(publicKey, privateKey, error);
    }

    public byte[] curve25519PreComputeSharedKey(byte[] peerPublicKey, byte[] localPrivateKey) {
        RawKey rawResult = raw.Curve25519PreComputeSharedKey(createPointer(peerPublicKey), createPointer(localPrivateKey));
        return rawResult.r0.getByteArray(0, rawResult.r1);
    }

    public byte[] ripemd160Hash(byte[] input) {
        RawKey rawResult = raw.Ripemd160Hash(createPointer(input), input.length);
        return rawResult.r0.getByteArray(0, rawResult.r1);
    }

    public byte[] sha256Hash(byte[] input) {
        RawKey rawResult = raw.Sha256Hash(createPointer(input), input.length);
        return rawResult.r0.getByteArray(0, rawResult.r1);
    }

    public byte[] ed25519GeneratePrivateKey() {
        RawKey rawResult = raw.Ed25519GeneratePrivateKey();
        return rawResult.r0.getByteArray(0, rawResult.r1);
    }

    public KeyError ed25519PublicKey(byte[] privateKey) {
        RawKeyError rawResult = raw.Ed25519PublicKey(createPointer(privateKey), privateKey.length);
        byte[] publicKey = rawResult.r0.getByteArray(0, rawResult.r1);
        String error = rawResult.r2;
        return new KeyError(publicKey, error);
    }

    private static Pointer createPointer(byte[] data) {
        Pointer pointer = new Memory(data.length + 1);
        pointer.write(0, data, 0, data.length);
        pointer.setByte(data.length, (byte) 0);
        return pointer;
    }

    public static GoBytom load() {
        GoBytomRaw raw = Native.loadLibrary("bytom-exports", GoBytomRaw.class);
        return new GoBytom(raw);
    }
}
