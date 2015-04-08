package cuenen.raymond.gn.packet;

import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnHeader;
import cuenen.raymond.gn.packet.namednumber.GnPacketHeaderType;
import cuenen.raymond.gn.packet.namednumber.GnTransportType;
import cuenen.raymond.gn.util.BitValues;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.*;

public final class GnCommonHeader implements GnHeader {

    private static final int NH_OFFSET = 0;
    private static final int NH_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int HT_HST_OFFSET = NH_OFFSET + NH_SIZE;
    private static final int HT_HST_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int TC_OFFSET = HT_HST_OFFSET + HT_HST_SIZE;
    private static final int TC_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int FLAGS_OFFSET = TC_OFFSET + TC_SIZE;
    private static final int FLAGS_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int PL_OFFSET = FLAGS_OFFSET + FLAGS_SIZE;
    private static final int PL_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int MHL_OFFSET = PL_OFFSET + PL_SIZE;
    private static final int MHL_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int RESERVED_OFFSET = MHL_OFFSET + MHL_SIZE;
    private static final int RESERVED_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int COMMON_HEADER_SIZE = RESERVED_OFFSET + RESERVED_SIZE;

    private final GnTransportType nextHeader;
    private final byte reserved1;
    private final GnPacketHeaderType extendedHeader;
    private final byte trafficClass;
    private final byte flags;
    private final short payloadLength;
    private final byte maximumHopLimit;
    private final byte reserved2;

    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param rawData
     * @param offset
     * @param length
     * @return a new GnCommonHeader object.
     * @throws org.pcap4j.packet.IllegalRawDataException
     */
    public static GnCommonHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new GnCommonHeader(rawData, offset, length);
    }

    private GnCommonHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        if (length < COMMON_HEADER_SIZE) {
            throw new IllegalRawDataException("The data is too short to build a Common header");
        }
        byte val = ByteArrays.getByte(rawData, NH_OFFSET + offset);
        nextHeader = GnTransportType.getInstance((byte) ((val >> 4) & 0x0F));
        reserved1 = (byte) (val & 0x0F);
        extendedHeader = GnPacketHeaderType.getInstance(ByteArrays.getByte(rawData, HT_HST_OFFSET + offset));
        trafficClass = ByteArrays.getByte(rawData, TC_OFFSET + offset);
        flags = ByteArrays.getByte(rawData, FLAGS_OFFSET + offset);
        payloadLength = ByteArrays.getShort(rawData, PL_OFFSET + offset);
        maximumHopLimit = ByteArrays.getByte(rawData, MHL_OFFSET + offset);
        reserved2 = ByteArrays.getByte(rawData, RESERVED_OFFSET + offset);
    }

    public GnTransportType getNextHeader() {
        return nextHeader;
    }

    public byte getReserved1() {
        return reserved1;
    }

    public GnPacketHeaderType getExtendedHeader() {
        return extendedHeader;
    }

    public byte getTrafficClass() {
        return trafficClass;
    }

    public byte getFlags() {
        return flags;
    }

    public short getPayloadLength() {
        return payloadLength;
    }

    public byte getMaximumHopLimit() {
        return maximumHopLimit;
    }

    public byte getReserved2() {
        return reserved2;
    }

    @Override
    public int length() {
        return COMMON_HEADER_SIZE;
    }

    @Override
    public byte[] rawData() {
        final byte[] rawData = new byte[COMMON_HEADER_SIZE];
        rawData[NH_OFFSET] = (byte) ((nextHeader.value() << 4) | reserved1);
        rawData[HT_HST_OFFSET] = extendedHeader.value();
        rawData[TC_OFFSET] = trafficClass;
        rawData[FLAGS_OFFSET] = flags;
        rawData[PL_OFFSET] = (byte) (payloadLength >> 8);
        rawData[PL_OFFSET + 1] = (byte) payloadLength;
        rawData[MHL_OFFSET] = maximumHopLimit;
        rawData[RESERVED_OFFSET] = reserved2;
        return rawData;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        final String ls = System.getProperty("line.separator");
        sb.append("[Common Header (").append(length()).append(" bytes)]").append(ls);
        sb.append("  ").append(BitValues.toBinaryString(nextHeader.value(), 4));
        sb.append(".... = Next Header: ").append(nextHeader).append(ls);
        sb.append("  ....").append(BitValues.toBinaryString(reserved1, 4));
        sb.append(" = Reserved: ").append(reserved1).append(ls);
        final int headerType = BitValues.getValue(extendedHeader.value(), 0, 4);
        final int headerSubtype = BitValues.getValue(extendedHeader.value(), 4, 4);
        sb.append("  ").append(BitValues.toBinaryString(headerType, 4));
        sb.append(".... = Header Type: ").append(extendedHeader).append(ls);
        sb.append("  ....").append(BitValues.toBinaryString(headerSubtype, 4));
        sb.append(" = Header Subtype: ").append(extendedHeader.getSubtype()).append(ls);
        sb.append("  Traffic Class: 0x").append(ByteArrays.toHexString(trafficClass, "")).append(ls);
        final int scf = BitValues.getValue(trafficClass, 0, 1);
        final int channelOffload = BitValues.getValue(trafficClass, 1, 1);
        final int tcId = BitValues.getValue(trafficClass, 2, 6);
        sb.append("    ").append(BitValues.toBinaryString(scf, 1));
        sb.append("....... = Store-Carry-Forward: ").append(scf).append(ls);
        sb.append("    .").append(BitValues.toBinaryString(channelOffload, 1));
        sb.append("...... = Channel Offload: ").append(channelOffload).append(ls);
        sb.append("    ..").append(BitValues.toBinaryString(tcId, 6));
        sb.append(" = TC ID (DCC Profile Id): ").append(tcId).append(ls);
        sb.append("  Flags: 0x").append(ByteArrays.toHexString(flags, "")).append(ls);
        final int mobile = BitValues.getValue(flags, 0, 1);
        final byte reserved = (byte) BitValues.getValue(flags, 1, 7);
        sb.append("    ").append(BitValues.toBinaryString(mobile, 1));
        sb.append("....... = Mobile Flag: ").append(mobile == 1 ? "Mobile" : "Stationary");
        sb.append(" (").append(mobile).append(')').append(ls);
        sb.append("    .").append(BitValues.toBinaryString(reserved, 7));
        sb.append(" = Reserved: 0x").append(ByteArrays.toHexString(reserved, "")).append(ls);
        sb.append("  Payload Length: ").append(payloadLength & 0xFFFF).append(ls);
        sb.append("  Maximum Hop Limit: ").append(maximumHopLimit & 0xFF).append(ls);
        sb.append("  Reserved: ").append(reserved2 & 0xFF).append(ls);
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof GnCommonHeader) {
            GnCommonHeader that = (GnCommonHeader) obj;
            return this.nextHeader.equals(that.nextHeader)
                    && this.reserved1 == that.reserved1
                    && this.extendedHeader.equals(that.extendedHeader)
                    && this.trafficClass == that.trafficClass
                    && this.flags == that.flags
                    && this.payloadLength == that.payloadLength
                    && this.maximumHopLimit == that.maximumHopLimit
                    && this.reserved2 == that.reserved2;
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 1;
        hash = hash * 41 + nextHeader.hashCode();
        hash = hash * 41 + reserved1;
        hash = hash * 41 + extendedHeader.hashCode();
        hash = hash * 41 + trafficClass;
        hash = hash * 41 + flags;
        hash = hash * 41 + payloadLength;
        hash = hash * 41 + maximumHopLimit;
        hash = hash * 41 + reserved2;
        return hash;
    }
}
