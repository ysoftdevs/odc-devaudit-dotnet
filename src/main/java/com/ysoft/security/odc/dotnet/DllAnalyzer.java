package com.ysoft.security.odc.dotnet;

import java.io.*;
import java.nio.charset.StandardCharsets;

public class DllAnalyzer {

    public static boolean isDotNet(RandomAccessFile in) throws IOException {
        /*
        Excerpt from https://www.darwinsys.com/file/ sources at magic/Magdir/msdos:
        0	string/b	MZ
        # If the relocation table is 0x40 or more bytes into the file, it's definitely
        # not a DOS EXE.
        >0x18  leshort >0x3f
        # Maybe it's a PE?
        >>(0x3c.l) string PE\0\0 PE
        >>>(0x3c.l+24)	leshort		0x010b
        >>>>(0x3c.l+232) lelong	>0	Mono/.Net assembly

        explanation: .l – little endian unsigned long
        For more, see `man magic`.
        */

        // Check MZ
        {
            in.seek(0);
            if (!checkString(in, "MZ")) {
                return false;
            }
        }

        // Check relocation table size
        {
            in.seek(0x18);
            final int relocationTableSize = readLittleEndianUnsignedShort(in);
            if(relocationTableSize < 0x40) {
                return false;
            }
        }

        in.seek(0x3c);
        final long base = readLittleEndianLong(in);

        // Check if it is PE
        {
            in.seek(base);
            if(!checkString(in, "PE\0\0")){
                return false;
            }
        }

        // Check .NET
        {
            in.seek(base+24);
            if(readLittleEndianUnsignedShort(in) != 0x010b){
                return false;
            }
            in.seek(base+232);
            return readLittleEndianLong(in) > 0;
        }

    }

    private static boolean checkString(RandomAccessFile in, String asciiString) throws IOException {
        return checkString(in, asciiString.getBytes(StandardCharsets.US_ASCII));
    }

    private static boolean checkString(RandomAccessFile in, byte[] bytes) throws IOException {
        for (final byte expectedByte : bytes) {
            final byte b = in.readByte();
            if (b != expectedByte) {
                return false;
            }
        }
        return true;
    }

    private static int readLittleEndianUnsignedShort(RandomAccessFile in) throws IOException {
        final byte buffer0 = in.readByte();
        final byte buffer1 = in.readByte();

        return
                (buffer0 & 0xFF) |
                        (buffer1 & 0xFF) << 8;

    }

    private static long readLittleEndianLong(DataInput in) throws IOException {
        final byte buffer0 = in.readByte();
        final byte buffer1 = in.readByte();
        final byte buffer2 = in.readByte();
        final byte buffer3 = in.readByte();

        return
                (buffer0 & 0xFF) |
                        (buffer1 & 0xFF) << 8 |
                        (buffer2 & 0xFF) << 16 |
                        (buffer3 & 0xFF) << 24;
    }

    public static boolean isDotNet(File file) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            return isDotNet(raf);
        }
    }
}
