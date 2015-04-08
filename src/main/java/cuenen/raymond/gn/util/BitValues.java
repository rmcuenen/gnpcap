package cuenen.raymond.gn.util;

import static org.pcap4j.util.ByteArrays.*;

public final class BitValues {

    public static int getValue(byte value, int offset, int length) {
        return getValue(offset, offset, length, BYTE_SIZE_IN_BITS);
    }

    public static int getValue(short value, int offset, int length) {
        return getValue(offset, offset, length, BYTE_SIZE_IN_BITS * SHORT_SIZE_IN_BYTES);
    }

    private static int getValue(int value, int offset, int length, int size) {
        if (length == 0) {
            throw new IllegalArgumentException("length is zero.");
        }
        if (offset < 0 || length < 0 || offset + length > size) {
            throw new ArrayIndexOutOfBoundsException();
        }
        int shift = size - offset - length;
        int mask = (1 << length) - 1;
        return (value >> shift) & mask;
    }

    public static String toBinaryString(int value, int bits) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 1 << (bits - 1); i > 0; i /= 2) {
            if ((value & i) != 0) {
                sb.append('1');
            } else {
                sb.append('0');
            }
        }
        return sb.toString();
    }

    private BitValues() {

    }
}
