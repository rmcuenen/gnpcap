package cuenen.raymond.gn.util;

import cuenen.raymond.gn.packet.namednumber.ItsStationType;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.*;

public final class LongPositionVector {

    private static final int GN_ADDR_OFFSET = 0;
    private static final int TST_OFFSET = GN_ADDR_OFFSET + GnAddress.SIZE_IN_BYTES;
    private static final int TST_SIZE = INT_SIZE_IN_BYTES;
    private static final int LAT_OFFSET = TST_OFFSET + TST_SIZE;
    private static final int LAT_SIZE = INT_SIZE_IN_BYTES;
    private static final int LONG_OFFSET = LAT_OFFSET + LAT_SIZE;
    private static final int LONG_SIZE = INT_SIZE_IN_BYTES;
    private static final int PAI_S_OFFSET = LONG_OFFSET + LONG_SIZE;
    private static final int PAI_S_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int H_OFFSET = PAI_S_OFFSET + PAI_S_SIZE;
    private static final int H_SIZE = SHORT_SIZE_IN_BYTES;
    public static final int LONG_POSITION_VECTOR_SIZE = H_OFFSET + H_SIZE;

    private final GnAddress gnAddress;
    private final int tst;
    private final int latitude;
    private final int longitude;
    private final byte pai;
    private final short speed;
    private final short heading;

    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param rawData
     * @param offset
     * @param length
     * @return a new LongPositionVector object.
     * @throws org.pcap4j.packet.IllegalRawDataException
     */
    public static LongPositionVector newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new LongPositionVector(rawData, offset, length);
    }

    private LongPositionVector(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        if (length < LONG_POSITION_VECTOR_SIZE) {
            throw new IllegalRawDataException("The data is too short to build a Long Position Vector");
        }
        gnAddress = GnAddress.getByAddress(ByteArrays.getSubArray(rawData, GN_ADDR_OFFSET + offset, GnAddress.SIZE_IN_BYTES));
        tst = ByteArrays.getInt(rawData, TST_OFFSET + offset);
        latitude = ByteArrays.getInt(rawData, LAT_OFFSET + offset);
        longitude = ByteArrays.getInt(rawData, LONG_OFFSET + offset);
        final short val = ByteArrays.getShort(rawData, PAI_S_OFFSET + offset);
        pai = (byte) BitValues.getValue(val, 0, 1);
        speed = (short) BitValues.getValue(val, 1, 15);
        heading = ByteArrays.getShort(rawData, H_OFFSET + offset);
    }

    public GnAddress getGnAddress() {
        return gnAddress;
    }

    public int getTst() {
        return tst;
    }

    public int getLatitude() {
        return latitude;
    }

    public int getLongitude() {
        return longitude;
    }

    public byte getPai() {
        return pai;
    }

    public short getSpeed() {
        return speed;
    }

    public short getHeading() {
        return heading;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        final String ls = System.getProperty("line.separator");
        sb.append("GN Adress: 0x").append(ByteArrays.toHexString(gnAddress.getAddress(), "")).append(ls);
        final boolean manual = gnAddress.isManuallyConfigured();
        sb.append("  ").append(manual ? "1" : "0");
        sb.append("............... = Assignment: ").append(manual ? "Manual" : "Automatic");
        sb.append(" (").append(manual ? "1)" : "0)").append(ls);
        final ItsStationType stationType = gnAddress.getStationType();
        sb.append("  .").append(BitValues.toBinaryString(stationType.value(), 5));
        sb.append(".......... = Station Type: ").append(stationType).append(ls);
        final int countryCode = gnAddress.getCountryCode();
        sb.append("  ......").append(BitValues.toBinaryString(countryCode, 10));
        sb.append(" = Country Code: ").append(countryCode).append(ls);
        sb.append("  Link-Layer Address: ").append(gnAddress.getLinkLayerAddress()).append(ls);
        sb.append("Timestamp: ").append(tst & 0xFFFFFFFFL);
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof LongPositionVector) {
            LongPositionVector that = (LongPositionVector) obj;
            return this.gnAddress == that.gnAddress
                    && this.tst == that.tst
                    && this.latitude == that.latitude
                    && this.longitude == that.longitude
                    && this.pai == that.pai
                    && this.speed == that.speed
                    && this.heading == that.heading;
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 1;
        hash = hash * 41 + gnAddress.hashCode();
        hash = hash * 41 + tst;
        hash = hash * 41 + latitude;
        hash = hash * 41 + longitude;
        hash = hash * 41 + pai;
        hash = hash * 41 + speed;
        hash = hash * 41 + heading;
        return hash;
    }
}
