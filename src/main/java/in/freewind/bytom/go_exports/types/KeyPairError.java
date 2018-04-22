package in.freewind.bytom.go_exports.types;

public class KeyPairError {
    public final byte[] publicKey;
    public final byte[] privateKey;
    public final String error;

    public KeyPairError(byte[] publicKey, byte[] privateKey, String error) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.error = error;
    }
}
