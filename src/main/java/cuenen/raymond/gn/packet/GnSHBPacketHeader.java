package cuenen.raymond.gn.packet;

import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnPacketHeader;
import cuenen.raymond.gn.util.LongPositionVector;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;

public final class GnSHBPacketHeader implements GnPacketHeader {

    private static final int SO_PV_OFFSET = 0;
    private static final int RESERVED_OFFSET = SO_PV_OFFSET + LongPositionVector.SIZE_IN_BYTES;
    private static final int RESERVED_SIZE = INT_SIZE_IN_BYTES;
    private static final int SHB_PACKET_HEADER_SIZE = RESERVED_OFFSET + RESERVED_SIZE;

    private final LongPositionVector source;
    private final int reserved;

    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param rawData
     * @param offset
     * @param length
     * @return a new GnSHBPacketHeader object.
     * @throws org.pcap4j.packet.IllegalRawDataException
     */
    public static GnSHBPacketHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new GnSHBPacketHeader(rawData, offset, length);
    }

    private GnSHBPacketHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        if (length < SHB_PACKET_HEADER_SIZE) {
            throw new IllegalRawDataException("The data is too short to build a TSB packet header");
        }
        source = LongPositionVector.newInstance(rawData, SO_PV_OFFSET + offset, length - SO_PV_OFFSET);
        reserved = ByteArrays.getInt(rawData, RESERVED_OFFSET + offset);
    }

    @Override
    public LongPositionVector sourcePosition() {
        return source;
    }

    public int getReserved() {
        return reserved;
    }

    @Override
    public int length() {
        return SHB_PACKET_HEADER_SIZE;
    }

    @Override
    public byte[] rawData() {
        final byte[] rawData = new byte[SHB_PACKET_HEADER_SIZE];
        source.writeTo(rawData, SO_PV_OFFSET);
        rawData[RESERVED_OFFSET] = (byte) (reserved >> 24);
        rawData[RESERVED_OFFSET + 1] = (byte) (reserved >> 16);
        rawData[RESERVED_OFFSET + 2] = (byte) (reserved >> 8);
        rawData[RESERVED_OFFSET + 3] = (byte) reserved;
        return rawData;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        final String ls = System.getProperty("line.separator");
        sb.append("[Topology-Scoped Broadcast (").append(length()).append(" bytes)]").append(ls);
        sb.append("  Source Position Vector").append(ls);
        sb.append(source.buildString("    "));
        sb.append("  Reserved: 0x").append(ByteArrays.toHexString(reserved, "")).append(ls);
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof GnSHBPacketHeader) {
            GnSHBPacketHeader that = (GnSHBPacketHeader) obj;
            return this.source.equals(that.source)
                    && this.reserved == that.reserved;
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 1;
        hash = hash * 41 + source.hashCode();
        hash = hash * 41 + reserved;
        return hash;
    }
}
