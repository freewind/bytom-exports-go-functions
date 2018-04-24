package in.freewind.bytom.go_exports;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import in.freewind.bytom.go_exports.types.KeyError;
import in.freewind.bytom.go_exports.types.KeyPairError;
import in.freewind.bytom.go_exports.types.TwoByteArrays;
import in.freewind.bytom.go_exports.types.raw.RawByteArray;
import in.freewind.bytom.go_exports.types.raw.RawKeyError;
import in.freewind.bytom.go_exports.types.raw.RawKeyPairError;
import in.freewind.bytom.go_exports.types.raw.RawTwoByteArrays;

public class GoBytom {
    private final GoBytomRaw raw;

    private GoBytom(GoBytomRaw raw) {
        this.raw = raw;
    }

    public KeyPairError curve25519GenerateKeyPair() {
        RawKeyPairError result = raw.Curve25519GenerateKeyPair();
        return new KeyPairError(result.getKey1(), result.getKey2(), result.getError());
    }

    public byte[] curve25519PreComputeSharedKey(byte[] peerPublicKey, byte[] localPrivateKey) {
        assert (peerPublicKey.length == 32);
        assert (localPrivateKey.length == 32);
        RawByteArray result = raw.Curve25519PreComputeSharedKey(createPointer(peerPublicKey), createPointer(localPrivateKey));
        return result.getByteArray();
    }

    public byte[] ripemd160Hash(byte[] input) {
        RawByteArray result = raw.Ripemd160Hash(createPointer(input), input.length);
        return result.getByteArray();
    }

    public byte[] sha256Hash(byte[] input) {
        RawByteArray result = raw.Sha256Hash(createPointer(input), input.length);
        return result.getByteArray();
    }

    public byte[] ed25519GeneratePrivateKey() {
        RawByteArray result = raw.Ed25519GeneratePrivateKey();
        return result.getByteArray();
    }

    public KeyError ed25519PublicKey(byte[] privateKey) {
        RawKeyError result = raw.Ed25519PublicKey(createPointer(privateKey), privateKey.length);
        return new KeyError(result.getByteArray(), result.getError());
    }

    public byte[] ed25519Sign(byte[] privateKey, byte[] data) {
        assert (privateKey.length == 64);
        RawByteArray rawResult = raw.Ed25519Sign(createPointer(privateKey), privateKey.length, createPointer(data), data.length);
        return rawResult.getByteArray();
    }

    public byte[] secretboxSeal(byte[] message, byte[] nonce, byte[] key) {
        assert (nonce.length == 24);
        assert (key.length == 32);
        RawByteArray rawResult = raw.SecretboxSeal(createPointer(message), message.length, createPointer(nonce), nonce.length, createPointer(key), key.length);
        return rawResult.getByteArray();
    }

    public byte[] secretboxOpen(byte[] box, byte[] nonce, byte[] key) {
        assert (nonce.length == 24);
        assert (key.length == 32);
        RawByteArray rawResult = raw.SecretboxOpen(createPointer(box), box.length, createPointer(nonce), nonce.length, createPointer(key), key.length);
        return rawResult.getByteArray();
    }

    public byte[] wire_TwoByteArrays(byte[] array1, byte[] array2) {
        RawByteArray result = raw.Wire_TwoByteArrays(createPointer(array1), array1.length, createPointer(array2), array2.length);
        return result.getByteArray();
    }

    public TwoByteArrays unwire_TwoByteArrays(byte[] data) {
        RawTwoByteArrays result = raw.Unwire_TwoByteArrays(createPointer(data), data.length);
        return new TwoByteArrays(result.getByteArray1(), result.getByteArray2());
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
