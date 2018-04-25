package in.freewind.bytom.go_exports;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import in.freewind.bytom.go_exports.types.KeyPairError;
import in.freewind.bytom.go_exports.types.AuthSigMessage;
import in.freewind.bytom.go_exports.types.raw.RawByteArray;
import in.freewind.bytom.go_exports.types.raw.RawKeyPairError;
import in.freewind.bytom.go_exports.types.raw.RawAuthSigMessage;

public class GoBytom {
    private final GoBytomRaw raw;

    private GoBytom(GoBytomRaw raw) {
        this.raw = raw;
    }

    public KeyPairError curve25519GenerateKeyPair() {
        RawKeyPairError result = raw.Curve25519GenerateKeyPair();
        byte[] publicKey = result.getKey1();
        byte[] privateKey = result.getKey2();
        checkLength("publicKey.length", publicKey, 32);
        checkLength("privateKey.length", privateKey, 32);
        return new KeyPairError(publicKey, privateKey, result.getError());
    }

    public byte[] curve25519PreComputeSharedKey(byte[] peerPublicKey, byte[] localPrivateKey) {
        checkLength("peerPublicKey.length", peerPublicKey, 32);
        checkLength("localPrivateKey.length", localPrivateKey, 32);
        RawByteArray result = raw.Curve25519PreComputeSharedKey(createPointer(peerPublicKey), 32, createPointer(localPrivateKey), 32);
        byte[] sharedKey = result.getByteArray();
        checkLength("sharedKey.length", sharedKey, 32);
        return sharedKey;
    }

    public byte[] ripemd160Hash(byte[] input) {
        RawByteArray result = raw.Ripemd160Hash(createPointer(input), input.length);
        byte[] hash = result.getByteArray();
        checkLength("hash.length", hash, 20);
        return hash;
    }

    public byte[] sha256Hash(byte[] input) {
        RawByteArray result = raw.Sha256Hash(createPointer(input), input.length);
        byte[] hash = result.getByteArray();
        checkLength("hash.length", hash, 32);
        return hash;
    }

    public byte[] ed25519GeneratePrivateKey() {
        RawByteArray result = raw.Ed25519GeneratePrivateKey();
        byte[] key = result.getByteArray();
        checkLength("privateKey.length", key, 64);
        return key;
    }

    public byte[] ed25519PublicKey(byte[] privateKey) {
        checkLength("privateKey.length", privateKey, 64);
        RawByteArray result = raw.Ed25519PublicKey(createPointer(privateKey), privateKey.length);
        byte[] publicKey = result.getByteArray();
        checkLength("publicKey.length", publicKey, 32);
        return publicKey;
    }

    public byte[] ed25519Sign(byte[] privateKey, byte[] data) {
        checkLength("privateKey.length", privateKey, 64);
        RawByteArray rawResult = raw.Ed25519Sign(createPointer(privateKey), privateKey.length, createPointer(data), data.length);
        byte[] signature = rawResult.getByteArray();
        checkLength("signature.length", signature, 64);
        return signature;
    }

    public byte[] secretboxSeal(byte[] message, byte[] nonce, byte[] key) {
        checkLength("nonce.length", nonce, 24);
        checkLength("key.length", key, 32);
        RawByteArray rawResult = raw.SecretboxSeal(createPointer(message), message.length, createPointer(nonce), nonce.length, createPointer(key), key.length);
        return rawResult.getByteArray();
    }

    public byte[] secretboxOpen(byte[] box, byte[] nonce, byte[] key) {
        checkLength("nonce.length", nonce, 24);
        checkLength("key.length", key, 32);
        RawByteArray rawResult = raw.SecretboxOpen(createPointer(box), box.length, createPointer(nonce), nonce.length, createPointer(key), key.length);
        return rawResult.getByteArray();
    }

    public byte[] wire_OneByteArray(byte[] array) {
        RawByteArray rawResult = raw.Wire_OneByteArray(createPointer(array), array.length);
        return rawResult.getByteArray();
    }

    public byte[] unwire_OneByteArray(byte[] array) {
        RawByteArray rawResult = raw.Unwire_OneByteArray(createPointer(array), array.length);
        return rawResult.getByteArray();
    }

    public byte[] wire_AuthSigMessage(byte[] array1, byte[] array2) {
        RawByteArray result = raw.Wire_AuthSigMessage(createPointer(array1), array1.length, createPointer(array2), array2.length);
        return result.getByteArray();
    }

    public AuthSigMessage unwire_AuthSigMessage(byte[] data) {
        RawAuthSigMessage result = raw.Unwire_AuthSigMessage(createPointer(data), data.length);
        return new AuthSigMessage(result.getByteArray1(), result.getByteArray2());
    }

    public Boolean ed25519VerifySignature(byte[] publicKey, byte[] message, byte[] signature) {
        checkLength("publicKey.length", publicKey, 32);
        return raw.Ed25519VerifySignature(createPointer(publicKey), publicKey.length, createPointer(message), message.length, createPointer(signature), signature.length);
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

    private static void checkLength(String name, byte[] array, int expectedValue) {
        if (array == null) {
            throw new IllegalArgumentException(name + ", expect a byte array with length " + expectedValue + ", actual: " + null);
        }
        if (array.length != expectedValue) {
            throw new IllegalArgumentException(name + ", expect: " + expectedValue + ", actual: " + array.length);
        }
    }
}
