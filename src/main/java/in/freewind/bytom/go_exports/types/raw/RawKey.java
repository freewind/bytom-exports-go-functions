package in.freewind.bytom.go_exports.types.raw;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public class RawKey extends Structure implements Structure.ByValue {
    public Pointer r0;
    public int r1;

    protected List<String> getFieldOrder() {
        return Arrays.asList("r0", "r1");
    }
}
