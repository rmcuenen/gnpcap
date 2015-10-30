package cuenen.raymond.gn.util;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;

public final class GeoPosition {

    private static final int LAT_OFFSET = 0;
    private static final int LAT_SIZE = INT_SIZE_IN_BYTES;
    private static final int LONG_OFFSET = LAT_OFFSET + LAT_SIZE;
    private static final int LONG_SIZE = INT_SIZE_IN_BYTES;
    public static final int SIZE_IN_BYTES = LONG_OFFSET + LONG_SIZE;

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
     * @return a new GeoPosition object.
     * @throws org.pcap4j.packet.IllegalRawDataException
     */
    public static GeoPosition newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new GeoPosition(rawData, offset, length);
    }

    private GeoPosition(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        if (length < SIZE_IN_BYTES) {
            throw new IllegalRawDataException("The data is too short to build a GeoPosition");
        }
        latitude = ByteArrays.getInt(rawData, LAT_OFFSET + offset);
        longitude = ByteArrays.getInt(rawData, LONG_OFFSET + offset);
    }

    public int getLatitude() {
        return latitude;
    }

    public int getLongitude() {
        return longitude;
    }

    public void writeTo(byte[] rawData, int offset) {
        ByteArrays.validateBounds(rawData, offset, SIZE_IN_BYTES);
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
        if (obj instanceof GeoPosition) {
            GeoPosition that = (GeoPosition) obj;
            return this.latitude == that.latitude
                    && this.longitude == that.longitude;
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 1;
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
