package in.freewind.bytom.go_exports.types.raw;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public class RawKeyError extends Structure implements Structure.ByValue {
    public Pointer r0;
    public int r1;
    public String r2;

    public byte[] getByteArray() {
        if (r0 == null || r1 == 0) {
            return null;
        } else {
            return r0.getByteArray(0, r1);
        }
    }

    public String getError() {
        return r2;
    }

    protected List<String> getFieldOrder() {
        return Arrays.asList("r0", "r1", "r2");
    }
}
