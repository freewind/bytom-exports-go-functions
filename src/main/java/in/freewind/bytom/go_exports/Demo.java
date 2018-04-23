package in.freewind.bytom.go_exports;

import in.freewind.bytom.go_exports.types.KeyError;
import in.freewind.bytom.go_exports.types.KeyPairError;
import org.apache.commons.codec.binary.Hex;

import java.util.Arrays;

public class Demo {

    public static void main(String[] args) {
        GoBytom bytom = GoBytom.load();
        curve25519GenerateKeyPair(bytom);
        curve25519PreComputeSharedKey(bytom);
        ripemd160Hash(bytom);
        sha256Hash(bytom);
        ed25519GeneratePrivateKey(bytom);
        ed25519PublicKey(bytom);
        ed25519Sign(bytom);
        secretboxSealOpen(bytom);
        wire_TwoByteArrays(bytom);
    }

    private static void wire_TwoByteArrays(GoBytom bytom) {
        byte[] array1 = new byte[]{1, 2, 3};
        byte[] array2 = new byte[]{4, 5, 6};
        byte[] bytes = bytom.wire_TwoByteArrays(array1, array2);
        printBytes("bytes", bytes);
    }

    private static void secretboxSealOpen(GoBytom bytom) {
        byte[] message = new byte[]{1, 2, 3, 4, 5};
        byte[] nonce = new byte[]{1, 1, 1};
        byte[] privateKey = bytom.ed25519GeneratePrivateKey();
        byte[] box = bytom.secretboxSeal(message, nonce, privateKey);
        printBytes("box", box);
        byte[] open = bytom.secretboxOpen(box, nonce, privateKey);
        printBytes("open", open);
        System.out.println("Opened message should be same to original message: " + Arrays.equals(message, open));
    }

    private static void ed25519Sign(GoBytom bytom) {
        System.out.println("---------------- Ed25519Sign -----------------");
        byte[] privateKey = bytom.ed25519GeneratePrivateKey();
        byte[] data = new byte[]{1, 2, 3};
        byte[] signature = bytom.ed25519Sign(privateKey, data);
        printBytes("signature", signature);
    }

    private static void ed25519PublicKey(GoBytom bytom) {
        System.out.println("--------------- Ed25519PublicKey ------------------");
        byte[] privateKey = bytom.ed25519GeneratePrivateKey();
        printBytes("privateKey", privateKey);
        KeyError publicKey = bytom.ed25519PublicKey(privateKey);
        printBytes("publicKey", publicKey.key);
        System.out.println("error: " + publicKey.error);
    }

    private static void ed25519GeneratePrivateKey(GoBytom bytom) {
        System.out.println("--------------- Ed25519GeneratePrivateKey ------------------");
        byte[] privateKey = bytom.ed25519GeneratePrivateKey();
        printBytes("privateKey", privateKey);
    }

    private static void sha256Hash(GoBytom bytom) {
        System.out.println("--------------- Sha256Hash ------------------");
        byte[] hash = bytom.sha256Hash(new byte[]{1, 2, 3});
        printBytes("hash", hash);
    }

    private static void ripemd160Hash(GoBytom bytom) {
        System.out.println("--------------- Ripemd160Hash ------------------");
        byte[] hash = bytom.ripemd160Hash(new byte[]{1, 2, 3});
        printBytes("hash", hash);
    }

    private static void curve25519PreComputeSharedKey(GoBytom bytom) {
        System.out.println("-------------- curve25519PreComputeSharedKey curve25519PreComputeSharedKey");
        KeyPairError localKeyPair = bytom.curve25519GenerateKeyPair();
        KeyPairError peerKeyPair = bytom.curve25519GenerateKeyPair();
        byte[] sharedKey1 = bytom.curve25519PreComputeSharedKey(peerKeyPair.publicKey, localKeyPair.privateKey);
        printBytes("sharedKey1", sharedKey1);
        byte[] sharedKey2 = bytom.curve25519PreComputeSharedKey(localKeyPair.publicKey, peerKeyPair.privateKey);
        printBytes("sharedKey2", sharedKey2);
        System.out.println("sharedKey1 should == sharedKey2: " + Arrays.equals(sharedKey1, sharedKey2));
    }

    private static void curve25519GenerateKeyPair(GoBytom bytom) {
        System.out.println("----------------- Curve25519GenerateKeyPair -----------------");
        KeyPairError result = bytom.curve25519GenerateKeyPair();
        printBytes("public key", result.publicKey);
        printBytes("private key", result.privateKey);
        System.out.println("error: " + result.error);
    }

    private static void printBytes(String name, byte[] data) {
        System.out.println(name + ": " + new String(Hex.encodeHex(data)));
    }

}
