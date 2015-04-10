package cuenen.raymond.gn.packet;

import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnPacketHeader;
import cuenen.raymond.gn.packet.namednumber.ItsStationType;
import cuenen.raymond.gn.util.BitValues;
import cuenen.raymond.gn.util.GnAddress;
import cuenen.raymond.gn.util.LongPositionVector;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

public class GnLSRequestPacketHeader implements GnPacketHeader {

    private static final int SN_OFFSET = 0;
    private static final int SN_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int RESERVED_OFFSET = SN_OFFSET + SN_SIZE;
    private static final int RESERVED_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int SO_PV_OFFSET = RESERVED_OFFSET + RESERVED_SIZE;
    private static final int REQUEST_GN_ADDRESS_OFFSET = SO_PV_OFFSET + LongPositionVector.SIZE_IN_BYTES;
    private static final int LS_REQUEST_PACKET_HEADER_SIZE = REQUEST_GN_ADDRESS_OFFSET + GnAddress.SIZE_IN_BYTES;

    private final short sequenceNumber;
    private final short reserved;
    private final LongPositionVector source;
    private final GnAddress requestAddress;

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
    public static GnLSRequestPacketHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new GnLSRequestPacketHeader(rawData, offset, length);
    }

    private GnLSRequestPacketHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        if (length < LS_REQUEST_PACKET_HEADER_SIZE) {
            throw new IllegalRawDataException("The data is too short to build a GUC packet header");
        }
        sequenceNumber = ByteArrays.getShort(rawData, SN_OFFSET + offset);
        reserved = ByteArrays.getShort(rawData, RESERVED_OFFSET + offset);
        source = LongPositionVector.newInstance(rawData, SO_PV_OFFSET + offset, length - SO_PV_OFFSET);
        requestAddress = GnAddress.getByAddress(ByteArrays.getSubArray(rawData, REQUEST_GN_ADDRESS_OFFSET + offset, GnAddress.SIZE_IN_BYTES));
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

    public GnAddress getRequestAddress() {
        return requestAddress;
    }

    @Override
    public int length() {
        return LS_REQUEST_PACKET_HEADER_SIZE;
    }

    @Override
    public byte[] rawData() {
        final byte[] rawData = new byte[LS_REQUEST_PACKET_HEADER_SIZE];
        rawData[SN_OFFSET] = (byte) (sequenceNumber >> 8);
        rawData[SN_OFFSET + 1] = (byte) sequenceNumber;
        rawData[RESERVED_OFFSET] = (byte) (reserved >> 8);
        rawData[RESERVED_OFFSET + 1] = (byte) reserved;
        source.writeTo(rawData, SO_PV_OFFSET);
        System.arraycopy(requestAddress.getAddress(), 0, rawData, REQUEST_GN_ADDRESS_OFFSET, GnAddress.SIZE_IN_BYTES);
        return rawData;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        final String ls = System.getProperty("line.separator");
        sb.append("[LS Request (").append(length()).append(" bytes)]").append(ls);
        sb.append("  Sequence Number: ").append(sequenceNumber & 0xFFFF).append(ls);
        sb.append("  Reserved: 0x").append(ByteArrays.toHexString(reserved, "")).append(ls);
        sb.append("  Source Position Vector").append(ls);
        sb.append(source.buildString("    "));
        sb.append("Request GN Adress: 0x").append(ByteArrays.toHexString(requestAddress.getAddress(), "")).append(ls);
        final boolean manual = requestAddress.isManuallyConfigured();
        sb.append("  ").append(manual ? "1" : "0");
        sb.append("............... = Assignment: ").append(manual ? "Manual" : "Automatic");
        sb.append(" (").append(manual ? "1)" : "0)").append(ls);
        final ItsStationType stationType = requestAddress.getStationType();
        sb.append("  .").append(BitValues.toBinaryString(stationType.value(), 5));
        sb.append(".......... = Station Type: ").append(stationType).append(ls);
        final int countryCode = requestAddress.getCountryCode();
        sb.append("  ......").append(BitValues.toBinaryString(countryCode, 10));
        sb.append(" = Country Code: ").append(countryCode).append(ls);
        sb.append("  Link-Layer Address: ").append(requestAddress.getLinkLayerAddress()).append(ls);
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof GnLSRequestPacketHeader) {
            GnLSRequestPacketHeader that = (GnLSRequestPacketHeader) obj;
            return this.source.equals(that.source);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return 41 + source.hashCode();
    }
}
