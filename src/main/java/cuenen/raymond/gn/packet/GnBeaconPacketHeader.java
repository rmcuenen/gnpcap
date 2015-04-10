package cuenen.raymond.gn.packet;

import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnPacketHeader;
import cuenen.raymond.gn.util.LongPositionVector;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;

public class GnBeaconPacketHeader implements GnPacketHeader {

    private static final int SO_PV_OFFSET = 0;
    private static final int BEACON_PACKET_HEADER_SIZE = SO_PV_OFFSET + LongPositionVector.SIZE_IN_BYTES;

    private final LongPositionVector source;

    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param rawData
     * @param offset
     * @param length
     * @return a new GnBeaconPacketHeader object.
     * @throws org.pcap4j.packet.IllegalRawDataException
     */
    public static GnBeaconPacketHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new GnBeaconPacketHeader(rawData, offset, length);
    }

    private GnBeaconPacketHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        if (length < BEACON_PACKET_HEADER_SIZE) {
            throw new IllegalRawDataException("The data is too short to build a GUC packet header");
        }
        source = LongPositionVector.newInstance(rawData, SO_PV_OFFSET + offset, length - SO_PV_OFFSET);
    }

    @Override
    public LongPositionVector sourcePosition() {
        return source;
    }

    @Override
    public int length() {
        return BEACON_PACKET_HEADER_SIZE;
    }

    @Override
    public byte[] rawData() {
        final byte[] rawData = new byte[BEACON_PACKET_HEADER_SIZE];
        source.writeTo(rawData, SO_PV_OFFSET);
        return rawData;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        final String ls = System.getProperty("line.separator");
        sb.append("[Beacon (").append(length()).append(" bytes)]").append(ls);
        sb.append("  Source Position Vector").append(ls);
        sb.append(source.buildString("    "));
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof GnBeaconPacketHeader) {
            GnBeaconPacketHeader that = (GnBeaconPacketHeader) obj;
            return this.source.equals(that.source);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return 41 + source.hashCode();
    }
}
