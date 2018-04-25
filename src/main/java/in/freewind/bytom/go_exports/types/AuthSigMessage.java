package in.freewind.bytom.go_exports.types;

public class AuthSigMessage {

    public final byte[] publicKey;
    public final byte[] signature;

    public AuthSigMessage(byte[] publicKey, byte[] signature) {
        this.publicKey = publicKey;
        this.signature = signature;
    }
}
