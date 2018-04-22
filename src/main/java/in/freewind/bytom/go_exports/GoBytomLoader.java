package in.freewind.bytom.go_exports;

import com.sun.jna.Native;

public class GoBytomLoader {

    public static GoBytom load(String libPath) {
        GoBytomRaw raw = Native.loadLibrary(libPath, GoBytomRaw.class);
        return new GoBytom(raw);
    }

}
