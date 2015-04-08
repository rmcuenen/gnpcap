package cuenen.raymond.gn.packet;

import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnHeader;
import cuenen.raymond.gn.packet.namednumber.GnHeaderType;
import cuenen.raymond.gn.util.BitValues;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;

public final class GnBasicHeader implements GnHeader {

    private static final int VERSION_NH_OFFSET = 0;
    private static final int VERSION_NH_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int RESERVED_OFFSET = VERSION_NH_OFFSET + VERSION_NH_SIZE;
    private static final int RESERVED_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int LT_OFFSET = RESERVED_OFFSET + RESERVED_SIZE;
    private static final int LT_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int RHL_OFFSET = LT_OFFSET + LT_SIZE;
    private static final int RHL_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int BASIC_HEADER_SIZE = RHL_OFFSET + RHL_SIZE;

    private final byte version;
    private final GnHeaderType nextHeader;
    private final byte reserved;
    private final byte lifetime;
    private final byte remainingHopLimit;

    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param rawData
     * @param offset
     * @param length
     * @return a new GnBasicHeader object.
     * @throws org.pcap4j.packet.IllegalRawDataException
     */
    public static GnBasicHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new GnBasicHeader(rawData, offset, length);
    }

    private GnBasicHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        if (length < BASIC_HEADER_SIZE) {
            throw new IllegalRawDataException("The data is too short to build a Basic header");
        }
        final byte versionNH = ByteArrays.getByte(rawData, VERSION_NH_OFFSET + offset);
        version = (byte) ((versionNH >> 4) & 0x0F);
        nextHeader = GnHeaderType.getInstance((byte) (versionNH & 0x0F));
        reserved = ByteArrays.getByte(rawData, RESERVED_OFFSET + offset);
        lifetime = ByteArrays.getByte(rawData, LT_OFFSET + offset);
        remainingHopLimit = ByteArrays.getByte(rawData, RHL_OFFSET + offset);
    }

    public byte getVersion() {
        return version;
    }

    public GnHeaderType getNextHeader() {
        return nextHeader;
    }

    public byte getReserved() {
        return reserved;
    }

    public byte getLifetime() {
        return lifetime;
    }

    public byte getRouterHopLimit() {
        return remainingHopLimit;
    }

    @Override
    public int length() {
        return BASIC_HEADER_SIZE;
    }

    @Override
    public byte[] rawData() {
        final byte[] rawData = new byte[BASIC_HEADER_SIZE];
        rawData[VERSION_NH_OFFSET] = (byte) ((version << 4) | nextHeader.value());
        rawData[RESERVED_OFFSET] = reserved;
        rawData[LT_OFFSET] = lifetime;
        rawData[RHL_OFFSET] = remainingHopLimit;
        return rawData;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        final String ls = System.getProperty("line.separator");
        sb.append("[Basic Header (").append(length()).append(" bytes)]").append(ls);
        sb.append("  ").append(BitValues.toBinaryString(version, 4)).append(".... = Version: ").append(version).append(ls);
        sb.append("  ....").append(BitValues.toBinaryString(nextHeader.value(), 4)).append(" = Next Header: ").append(nextHeader).append(ls);
        sb.append("  Reserved: ").append(reserved & 0xFF).append(ls);
        final int[] ltBase = {50, 1, 10, 100};
        final int base = BitValues.getValue(lifetime, 6, 2);
        final int mult = BitValues.getValue(lifetime, 0, 6);
        sb.append("  Lifetime ").append(mult * ltBase[base]).append(base == 0 ? " ms" : " s").append(ls);
        sb.append("    ").append(BitValues.toBinaryString(mult, 6)).append(".. = Multiplier: ").append(mult).append(ls);
        sb.append("    ......").append(BitValues.toBinaryString(base, 2)).append(" = Base: ").append(ltBase[base]);
        sb.append(base == 0 ? " ms (" : " s (").append(base).append(')').append(ls);
        sb.append("  Router Hop Limit: ").append(remainingHopLimit & 0xFF).append(ls);
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof GnBasicHeader) {
            GnBasicHeader that = (GnBasicHeader) obj;
            return this.version == that.version
                    && this.nextHeader.equals(that.nextHeader)
                    && this.reserved == that.reserved
                    && this.lifetime == that.lifetime
                    && this.remainingHopLimit == that.remainingHopLimit;
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 1;
        hash = hash * 41 + version;
        hash = hash * 41 + nextHeader.hashCode();
        hash = hash * 41 + reserved;
        hash = hash * 41 + lifetime;
        hash = hash * 41 + remainingHopLimit;
        return hash;
    }
}
