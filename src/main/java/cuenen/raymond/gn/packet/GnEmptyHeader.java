package cuenen.raymond.gn.packet;

import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnPacketHeader;
import cuenen.raymond.gn.util.LongPositionVector;
import org.pcap4j.util.ByteArrays;

public final class GnEmptyHeader implements GnPacketHeader {

    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param rawData
     * @param offset
     * @param length
     * @return a new GnEmptyHeader object.
     */
    public static GnEmptyHeader newInstance(byte[] rawData, int offset, int length) {
        ByteArrays.validateBounds(rawData, offset, length);
        return new GnEmptyHeader(rawData, offset, length);
    }

    private GnEmptyHeader(byte[] rawData, int offset, int length) {
    }

    @Override
    public LongPositionVector sourcePosition() {
        return null;
    }

    @Override
    public int length() {
        return 0;
    }

    @Override
    public byte[] rawData() {
        return new byte[0];
    }

    @Override
    public String toString() {
        return "";
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof GnEmptyHeader;
    }

    @Override
    public int hashCode() {
        return 41;
    }
}
