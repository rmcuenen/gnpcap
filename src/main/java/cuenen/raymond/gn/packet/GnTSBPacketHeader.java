package cuenen.raymond.gn.packet;

import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnPacketHeader;
import cuenen.raymond.gn.util.LongPositionVector;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

public final class GnTSBPacketHeader implements GnPacketHeader {

    private static final int SN_OFFSET = 0;
    private static final int SN_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int RESERVED_OFFSET = SN_OFFSET + SN_SIZE;
    private static final int RESERVED_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int SO_PV_OFFSET = RESERVED_OFFSET + RESERVED_SIZE;
    private static final int TSB_PACKET_HEADER_SIZE = SO_PV_OFFSET + LongPositionVector.SIZE_IN_BYTES;

    private final short sequenceNumber;
    private final short reserved;
    private final LongPositionVector source;

    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param rawData
     * @param offset
     * @param length
     * @return a new GnTSBPacketHeader object.
     * @throws org.pcap4j.packet.IllegalRawDataException
     */
    public static GnTSBPacketHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new GnTSBPacketHeader(rawData, offset, length);
    }

    private GnTSBPacketHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        if (length < TSB_PACKET_HEADER_SIZE) {
            throw new IllegalRawDataException("The data is too short to build a TSB packet header");
        }
        sequenceNumber = ByteArrays.getShort(rawData, SN_OFFSET + offset);
        reserved = ByteArrays.getShort(rawData, RESERVED_OFFSET + offset);
        source = LongPositionVector.newInstance(rawData, SO_PV_OFFSET + offset, length - SO_PV_OFFSET);
    }

    public short getSequenceNumber() {
        return sequenceNumber;
    }

    public short getReserved() {
        return reserved;
    }

    @Override
    public LongPositionVector sourcePosition() {
        return source;
    }

    @Override
    public int length() {
        return TSB_PACKET_HEADER_SIZE;
    }

    @Override
    public byte[] rawData() {
        final byte[] rawData = new byte[TSB_PACKET_HEADER_SIZE];
        rawData[SN_OFFSET] = (byte) (sequenceNumber >> 8);
        rawData[SN_OFFSET + 1] = (byte) sequenceNumber;
        rawData[RESERVED_OFFSET] = (byte) (reserved >> 8);
        rawData[RESERVED_OFFSET + 1] = (byte) reserved;
        source.writeTo(rawData, SO_PV_OFFSET);
        return rawData;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        final String ls = System.getProperty("line.separator");
        sb.append("[Topology-Scoped Broadcast (").append(length()).append(" bytes)]").append(ls);
        sb.append("  Sequence Number: ").append(sequenceNumber & 0xFFFF).append(ls);
        sb.append("  Reserved: 0x").append(ByteArrays.toHexString(reserved, "")).append(ls);
        sb.append("  Source Position Vector").append(ls);
        sb.append(source.buildString("    "));
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof GnTSBPacketHeader) {
            GnTSBPacketHeader that = (GnTSBPacketHeader) obj;
            return this.sequenceNumber == that.sequenceNumber
                    && this.reserved == that.reserved
                    && this.source.equals(that.source);
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 1;
        hash = hash * 41 + sequenceNumber;
        hash = hash * 41 + reserved;
        hash = hash * 41 + source.hashCode();
        return hash;
    }
}
