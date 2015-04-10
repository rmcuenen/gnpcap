package cuenen.raymond.gn.util;

import static org.pcap4j.util.ByteArrays.*;

public final class BitValues {

    public static int getValue(byte value, int offset, int length) {
        if (length == 0) {
            throw new IllegalArgumentException("length is zero.");
        }
        if (offset < 0 || length < 0 || offset + length > BYTE_SIZE_IN_BITS) {
            throw new ArrayIndexOutOfBoundsException();
        }
        int shift = BYTE_SIZE_IN_BITS - offset - length;
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
