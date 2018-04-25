package in.freewind.bytom.go_exports;

import in.freewind.bytom.go_exports.types.KeyPairError;
import in.freewind.bytom.go_exports.types.AuthSigMessage;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;

public class Demo {

    public static void main(String[] args) throws Exception {
        GoBytom bytom = GoBytom.load();
        curve25519GenerateKeyPair(bytom);
        curve25519PreComputeSharedKey(bytom);
        ripemd160Hash(bytom);
        sha256Hash(bytom);
        ed25519GeneratePrivateKey(bytom);
        ed25519Sign(bytom);
        secretboxSealOpen(bytom);
        wire_OneByteArray(bytom);
        authSigMessage(bytom);
    }

    private static void wire_OneByteArray(GoBytom bytom) throws DecoderException {
        System.out.println("-------------- wire_OneByteArray & unwire_OneByteArray -----------------");
        byte[] array1 = hexToBytes("01 69 3c 9d 95 50 6e 33 7c 52 2c e0 c1 28 84 12 c6 7d 80 ab fd 8b c4 9c 43 2e b6 62 bd ef 7f 7a 6b");
        byte[] bytes = bytom.wire_OneByteArray(array1);
        printBytes("bytes", bytes);

        byte[] result = bytom.unwire_OneByteArray(bytes);
        printBytes("result", result);
        System.out.println("result should equal to array1: " + Arrays.equals(array1, result));
    }

    private static void authSigMessage(GoBytom bytom) throws DecoderException {
        System.out.println("-------------- wire_AuthSigMessage & unwire_AuthSigMessage -----------------");
        byte[] publicKey = hexToBytes("8D E1 98 8D 24 80 B9 EE D6 54 99 A4 58 54 D4 73 C7 6D 0A 2B B9 77 00 CC 90 57 D2 52 A1 1E 04 1A");
        byte[] signature = hexToBytes("EB E2 90 C6 FB 55 13 70 95 CF E0 8F B2 2A 7E 7A 57 07 7E C5 93 20 8A 69 FA 61 4C 88 5B D0 7F B0 69 18 05 60 90 3E 07 52 8A 70 12 8F A4 78 4B 85 01 BA AC 2A BD D0 15 47 0D 1A 59 C8 E9 C2 45 01");
        byte[] authSigMessage = bytom.wire_AuthSigMessage(publicKey, signature);
        byte[] expect = hexToBytes("01 8D E1 98 8D 24 80 B9 EE D6 54 99 A4 58 54 D4 73 C7 6D 0A 2B B9 77 00 CC 90 57 D2 52 A1 1E 04 1A 01 EB E2 90 C6 FB 55 13 70 95 CF E0 8F B2 2A 7E 7A 57 07 7E C5 93 20 8A 69 FA 61 4C 88 5B D0 7F B0 69 18 05 60 90 3E 07 52 8A 70 12 8F A4 78 4B 85 01 BA AC 2A BD D0 15 47 0D 1A 59 C8 E9 C2 45 01");
        printBytes("authSigMessage", authSigMessage);
        printBytes("expect", expect);
        System.out.println("authSigMessage should == expect: " + Arrays.equals(authSigMessage, expect));

        AuthSigMessage result = bytom.unwire_AuthSigMessage(authSigMessage);
        printBytes("publicKey", result.publicKey);
        printBytes("signature", result.signature);
    }

    private static byte[] hexToBytes(String str) throws DecoderException {
        return Hex.decodeHex(StringUtils.remove(str, " "));
    }

    private static void secretboxSealOpen(GoBytom bytom) {
        byte[] message = new byte[]{1, 2, 3, 4, 5};
        byte[] nonce = new byte[24];
        byte[] privateKey = bytom.curve25519GenerateKeyPair().privateKey;
        byte[] box = bytom.secretboxSeal(message, nonce, privateKey);
        printBytes("box", box);
        byte[] open = bytom.secretboxOpen(box, nonce, privateKey);
        printBytes("open", open);
        System.out.println("Opened message should be same to original message: " + Arrays.equals(message, open));
    }

    private static void ed25519Sign(GoBytom bytom) throws DecoderException {
        System.out.println("---------------- Ed25519Sign & Ed25519VerifySignature -----------------");
        byte[] privateKey = hexToBytes("10 53 46 FF B5 36 C1 29 0E AC 49 22 5A 4C 28 5C 00 12 B7 73 34 B3 B4 B3 4E F9 FF A4 CE 6D 6C CD 8D E1 98 8D 24 80 B9 EE D6 54 99 A4 58 54 D4 73 C7 6D 0A 2B B9 77 00 CC 90 57 D2 52 A1 1E 04 1A");
        byte[] data = hexToBytes("06 7A D4 17 F8 1B E4 48 EA C2 21 E8 0B 4C E7 01 A3 90 DC C7 39 C9 EB 60 6A 11 06 A1 92 D2 2F B2");
        byte[] signature = bytom.ed25519Sign(privateKey, data);
        byte[] expect = hexToBytes("EB E2 90 C6 FB 55 13 70 95 CF E0 8F B2 2A 7E 7A 57 07 7E C5 93 20 8A 69 FA 61 4C 88 5B D0 7F B0 69 18 05 60 90 3E 07 52 8A 70 12 8F A4 78 4B 85 01 BA AC 2A BD D0 15 47 0D 1A 59 C8 E9 C2 45 01");
        printBytes("signature", signature);
        printBytes("expect", expect);
        System.out.println("signature should == expect: " + Arrays.equals(signature, expect));

        byte[] publicKey = hexToBytes("8D E1 98 8D 24 80 B9 EE D6 54 99 A4 58 54 D4 73 C7 6D 0A 2B B9 77 00 CC 90 57 D2 52 A1 1E 04 1A");

        boolean ok = bytom.ed25519VerifySignature(publicKey, data, signature);
        System.out.println("Verify result should be true: " + ok);
    }

    private static void ed25519GeneratePrivateKey(GoBytom bytom) {
        System.out.println("--------------- Ed25519GeneratePrivateKey ------------------");
        byte[] privateKey = bytom.ed25519GeneratePrivateKey();
        printBytes("privateKey", privateKey);
        byte[] publicKey = bytom.ed25519PublicKey(privateKey);
        printBytes("publicKey", publicKey);
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
        System.out.println("-------------- curve25519PreComputeSharedKey ---------------------");
        KeyPairError localKeyPair = bytom.curve25519GenerateKeyPair();
        printBytes("localKeyPair.privateKey", localKeyPair.privateKey);
        printBytes("localKeyPair.publicKey", localKeyPair.publicKey);
        KeyPairError peerKeyPair = bytom.curve25519GenerateKeyPair();
        printBytes("peerKeyPair.publicKey", peerKeyPair.publicKey);
        printBytes("peerKeyPair.privateKey", peerKeyPair.privateKey);
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
        System.out.println(name + ": len(" + data.length + ") " + new String(Hex.encodeHex(data)));
    }

}
