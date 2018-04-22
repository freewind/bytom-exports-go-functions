package in.freewind.bytom.go_exports;

import in.freewind.bytom.go_exports.types.Curve25519GenerateKeyPair_Return;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;

import java.io.File;
import java.util.Arrays;

public class Demo {

    public static void main(String[] args) {
        GoBytom bytom = GoBytomLoader.load(new File("./go/bytom-exports.so").getAbsolutePath());
        curve25519GenerateKeyPair(bytom);
        curve25519PreComputeSharedKey(bytom);
    }

    private static void curve25519PreComputeSharedKey(GoBytom bytom) {
        System.out.println("-------------- curve25519PreComputeSharedKey curve25519PreComputeSharedKey");
        Curve25519GenerateKeyPair_Return localKeyPair = bytom.curve25519GenerateKeyPair();
        Curve25519GenerateKeyPair_Return peerKeyPair = bytom.curve25519GenerateKeyPair();
        byte[] sharedKey1 = bytom.curve25519PreComputeSharedKey(peerKeyPair.publicKey, localKeyPair.privateKey);
        printBytes("sharedKey1", sharedKey1);
        byte[] sharedKey2 = bytom.curve25519PreComputeSharedKey(localKeyPair.publicKey, peerKeyPair.privateKey);
        printBytes("sharedKey2", sharedKey2);
        System.out.println("sharedKey1 should == sharedKey2: " + Arrays.equals(sharedKey1, sharedKey2));
    }

    private static void curve25519GenerateKeyPair(GoBytom bytom) {
        System.out.println("----------------- Curve25519GenerateKeyPair -----------------");
        Curve25519GenerateKeyPair_Return result = bytom.curve25519GenerateKeyPair();
        printBytes("public key", result.publicKey);
        printBytes("private key", result.privateKey);
        System.out.println("error: " + result.error);
    }

    private static void printBytes(String name, byte[] data) {
        System.out.println(name + ": " + new String(Hex.encodeHex(data)));
    }


}
