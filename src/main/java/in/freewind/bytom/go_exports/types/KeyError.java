package in.freewind.bytom.go_exports.types;

public class KeyError {
    public final byte[] key;
    public final String error;

    public KeyError(byte[] key, String error) {
        this.key = key;
        this.error = error;
    }
}
