package in.freewind.bytom.go_exports.types.raw;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public class Curve25519GenerateKeyPair_RawReturn extends Structure implements Structure.ByValue {
    public Pointer r0;
    public int r1;
    public Pointer r2;
    public int r3;
    public String r4;

    protected List<String> getFieldOrder() {
        return Arrays.asList("r0", "r1", "r2", "r3", "r4");
    }

}