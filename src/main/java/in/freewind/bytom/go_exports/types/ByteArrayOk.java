package in.freewind.bytom.go_exports.types;

public class ByteArrayOk {
    public final byte[] key;
    public final boolean ok;

    public ByteArrayOk(byte[] data, boolean ok) {
        this.key = data;
        this.ok = ok;
    }
}
