package in.freewind.bytom.go_exports.types.raw;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public class RawKeyPairError extends Structure implements Structure.ByValue {
    public Pointer r0;
    public int r1;
    public Pointer r2;
    public int r3;
    public String r4;

    public byte[] getKey1() {
        if (r0 == null || r1 == 0) {
            return null;
        }
        return r0.getByteArray(0, r1);
    }

    public byte[] getKey2() {
        if (r2 == null || r3 == 0) {
            return null;
        }
        return r2.getByteArray(0, r3);
    }

    public String getError() {
        return r4;
    }

    protected List<String> getFieldOrder() {
        return Arrays.asList("r0", "r1", "r2", "r3", "r4");
    }

}
