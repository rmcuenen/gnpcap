package cuenen.raymond.gn.packet;

import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnPacketHeader;
import cuenen.raymond.gn.util.LongPositionVector;
import java.util.Arrays;
import org.pcap4j.util.ByteArrays;

public final class GnMalformedHeader implements GnPacketHeader {

    private final byte[] data;

    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param rawData
     * @param offset
     * @param length
     * @return a new GnMalformedHeader object.
     */
    public static GnMalformedHeader newInstance(byte[] rawData, int offset, int length) {
        ByteArrays.validateBounds(rawData, offset, length);
        return new GnMalformedHeader(rawData, offset, length);
    }

    private GnMalformedHeader(byte[] rawData, int offset, int length) {
        data = ByteArrays.getSubArray(rawData, offset, length);
    }

    @Override
    public LongPositionVector sourcePosition() {
        return null;
    }

    @Override
    public int length() {
        return data.length;
    }

    @Override
    public byte[] rawData() {
        return ByteArrays.clone(data);
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        final String ls = System.getProperty("line.separator");
        sb.append("[Malformed GN Header (").append(data.length).append(" bytes)]").append(ls);
        sb.append("  Hex stream: ").append(ByteArrays.toHexString(data, " ")).append(ls);
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof GnMalformedHeader) {
            GnMalformedHeader that = (GnMalformedHeader) obj;
            return Arrays.equals(this.data, that.data);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return 41 + Arrays.hashCode(data);
    }
}
