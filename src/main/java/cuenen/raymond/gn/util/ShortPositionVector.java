package cuenen.raymond.gn.util;

import cuenen.raymond.gn.packet.namednumber.ItsStationType;
import static cuenen.raymond.gn.util.LongPositionVector.SIZE_IN_BYTES;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;

public class ShortPositionVector {

    private static final int GN_ADDR_OFFSET = 0;
    private static final int TST_OFFSET = GN_ADDR_OFFSET + GnAddress.SIZE_IN_BYTES;
    private static final int TST_SIZE = INT_SIZE_IN_BYTES;
    private static final int LAT_OFFSET = TST_OFFSET + TST_SIZE;
    private static final int LAT_SIZE = INT_SIZE_IN_BYTES;
    private static final int LONG_OFFSET = LAT_OFFSET + LAT_SIZE;
    private static final int LONG_SIZE = INT_SIZE_IN_BYTES;
    public static final int SIZE_IN_BYTES = LONG_OFFSET + LONG_SIZE;

    private final GnAddress gnAddress;
    private final int tst;
    private final int latitude;
    private final int longitude;

    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param rawData
     * @param offset
     * @param length
     * @return a new ShortPositionVector object.
     * @throws org.pcap4j.packet.IllegalRawDataException
     */
    public static ShortPositionVector newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new ShortPositionVector(rawData, offset, length);
    }

    protected ShortPositionVector(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        if (length < SIZE_IN_BYTES) {
            throw new IllegalRawDataException("The data is too short to build a Short Position Vector");
        }
        gnAddress = GnAddress.getByAddress(ByteArrays.getSubArray(rawData, GN_ADDR_OFFSET + offset, GnAddress.SIZE_IN_BYTES));
        tst = ByteArrays.getInt(rawData, TST_OFFSET + offset);
        latitude = ByteArrays.getInt(rawData, LAT_OFFSET + offset);
        longitude = ByteArrays.getInt(rawData, LONG_OFFSET + offset);
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

    public void writeTo(byte[] rawData, int offset) {
        ByteArrays.validateBounds(rawData, offset, SIZE_IN_BYTES);
        System.arraycopy(gnAddress.getAddress(), 0, rawData, GN_ADDR_OFFSET + offset, GnAddress.SIZE_IN_BYTES);
        rawData[TST_OFFSET] = (byte) (tst << 24);
        rawData[TST_OFFSET + 1] = (byte) (tst << 16);
        rawData[TST_OFFSET + 2] = (byte) (tst << 8);
        rawData[TST_OFFSET + 3] = (byte) tst;
        rawData[LAT_OFFSET] = (byte) (latitude << 24);
        rawData[LAT_OFFSET + 1] = (byte) (latitude << 16);
        rawData[LAT_OFFSET + 2] = (byte) (latitude << 8);
        rawData[LAT_OFFSET + 3] = (byte) latitude;
        rawData[LONG_OFFSET] = (byte) (longitude << 24);
        rawData[LONG_OFFSET + 1] = (byte) (longitude << 16);
        rawData[LONG_OFFSET + 2] = (byte) (longitude << 8);
        rawData[LONG_OFFSET + 3] = (byte) longitude;
    }

    public String buildString(String prefix) {
        final StringBuilder sb = new StringBuilder();
        final String ls = System.getProperty("line.separator");
        sb.append(prefix).append("GN Adress: 0x").append(ByteArrays.toHexString(gnAddress.getAddress(), "")).append(ls);
        final boolean manual = gnAddress.isManuallyConfigured();
        sb.append(prefix).append("  ").append(manual ? "1" : "0");
        sb.append("............... = Assignment: ").append(manual ? "Manual" : "Automatic");
        sb.append(" (").append(manual ? "1)" : "0)").append(ls);
        final ItsStationType stationType = gnAddress.getStationType();
        sb.append(prefix).append("  .").append(BitValues.toBinaryString(stationType.value(), 5));
        sb.append(".......... = Station Type: ").append(stationType).append(ls);
        final int countryCode = gnAddress.getCountryCode();
        sb.append(prefix).append("  ......").append(BitValues.toBinaryString(countryCode, 10));
        sb.append(" = Country Code: ").append(countryCode).append(ls);
        sb.append(prefix).append("  Link-Layer Address: ").append(gnAddress.getLinkLayerAddress()).append(ls);
        sb.append(prefix).append("Timestamp: ").append(tst & 0xFFFFFFFFL).append(ls);
        final long lat = latitude & 0xFFFFFFFFL;
        final long lon = longitude & 0xFFFFFFFFL;
        sb.append(prefix).append("Latitude: ").append(fromDecimal(lat / 1E7, "NS"));
        sb.append(" (").append(lat).append(')').append(ls);
        sb.append(prefix).append("Longitude: ").append(fromDecimal(lon / 1E7, "EW"));
        sb.append(" (").append(lon).append(')').append(ls);
        return sb.toString();
    }

    @Override
    public String toString() {
        return buildString("");
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ShortPositionVector) {
            ShortPositionVector that = (ShortPositionVector) obj;
            return this.gnAddress == that.gnAddress
                    && this.tst == that.tst
                    && this.latitude == that.latitude
                    && this.longitude == that.longitude;
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
        return hash;
    }

    private String fromDecimal(double deg, String dir) {
        final double frac = (deg * 3600) % 3600;
        final int min = (int) (frac / 60);
        final double sec = frac % 60;
        final char h = dir.charAt(deg < 0 ? 1 : 0);
        return String.format("%02d\u00b0%02d'%4.02f\"%c", (int) deg, min, sec, h);
    }
}
