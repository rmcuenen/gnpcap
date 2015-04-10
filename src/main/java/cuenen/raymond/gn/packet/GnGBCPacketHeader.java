package cuenen.raymond.gn.packet;

import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnPacketHeader;
import cuenen.raymond.gn.util.LongPositionVector;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.*;

public class GnGBCPacketHeader implements GnPacketHeader {

    private static final int SN_OFFSET = 0;
    private static final int SN_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int RESERVED1_OFFSET = SN_OFFSET + SN_SIZE;
    private static final int RESERVED1_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int SO_PV_OFFSET = RESERVED1_OFFSET + RESERVED1_SIZE;
    private static final int GEO_AREA_POS_LATITUDE_OFFSET = SO_PV_OFFSET + LongPositionVector.SIZE_IN_BYTES;
    private static final int GEO_AREA_POS_LATITUDE_SIZE = INT_SIZE_IN_BYTES;
    private static final int GEO_AREA_POS_LONGITUDE_OFFSET = GEO_AREA_POS_LATITUDE_OFFSET + GEO_AREA_POS_LATITUDE_SIZE;
    private static final int GEO_AREA_POS_LONGITUDE_SIZE = INT_SIZE_IN_BYTES;
    private static final int DISTANCE_A_OFFSET = GEO_AREA_POS_LONGITUDE_OFFSET + GEO_AREA_POS_LONGITUDE_SIZE;
    private static final int DISTANCE_A_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int DISTANCE_B_OFFSET = DISTANCE_A_OFFSET + DISTANCE_A_SIZE;
    private static final int DISTANCE_B_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int ANGLE_OFFSET = DISTANCE_B_OFFSET + DISTANCE_B_SIZE;
    private static final int ANGLE_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int RESERVED2_OFFSET = ANGLE_OFFSET + ANGLE_SIZE;
    private static final int RESERVED2_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int GBC_PACKET_HEADER_SIZE = RESERVED2_OFFSET + RESERVED2_SIZE;

    private final short sequenceNumber;
    private final short reserved1;
    private final LongPositionVector source;
    private final int latitude;
    private final int longitude;
    private final short distanceA;
    private final short distanceB;
    private final short angle;
    private final short reserved2;

    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param rawData
     * @param offset
     * @param length
     * @return a new GnGBCPacketHeader object.
     * @throws org.pcap4j.packet.IllegalRawDataException
     */
    public static GnGBCPacketHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new GnGBCPacketHeader(rawData, offset, length);
    }

    private GnGBCPacketHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        if (length < GBC_PACKET_HEADER_SIZE) {
            throw new IllegalRawDataException("The data is too short to build a GUC packet header");
        }
        sequenceNumber = ByteArrays.getShort(rawData, SN_OFFSET + offset);
        reserved1 = ByteArrays.getShort(rawData, RESERVED1_OFFSET + offset);
        source = LongPositionVector.newInstance(rawData, SO_PV_OFFSET + offset, length - SO_PV_OFFSET);
        latitude = ByteArrays.getInt(rawData, GEO_AREA_POS_LATITUDE_OFFSET + offset);
        longitude = ByteArrays.getInt(rawData, GEO_AREA_POS_LONGITUDE_OFFSET + offset);
        distanceA = ByteArrays.getShort(rawData, DISTANCE_A_OFFSET + offset);
        distanceB = ByteArrays.getShort(rawData, DISTANCE_B_OFFSET + offset);
        angle = ByteArrays.getShort(rawData, ANGLE_OFFSET + offset);
        reserved2 = ByteArrays.getShort(rawData, RESERVED2_OFFSET + offset);
    }

    public short getSequenceNumber() {
        return sequenceNumber;
    }

    public short getReserved1() {
        return reserved1;
    }

    @Override
    public LongPositionVector sourcePosition() {
        return source;
    }

    public int getLatitude() {
        return latitude;
    }

    public int getLongitude() {
        return longitude;
    }

    public short getDistanceA() {
        return distanceA;
    }

    public short getDistanceB() {
        return distanceB;
    }

    public short getAngle() {
        return angle;
    }

    public short getReserved2() {
        return reserved2;
    }

    @Override
    public int length() {
        return GBC_PACKET_HEADER_SIZE;
    }

    @Override
    public byte[] rawData() {
        final byte[] rawData = new byte[GBC_PACKET_HEADER_SIZE];
        rawData[SN_OFFSET] = (byte) (sequenceNumber >> 8);
        rawData[SN_OFFSET + 1] = (byte) sequenceNumber;
        rawData[RESERVED1_OFFSET] = (byte) (reserved1 >> 8);
        rawData[RESERVED1_OFFSET + 1] = (byte) reserved1;
        source.writeTo(rawData, SO_PV_OFFSET);
        rawData[GEO_AREA_POS_LATITUDE_OFFSET] = (byte) (latitude >> 24);
        rawData[GEO_AREA_POS_LATITUDE_OFFSET + 1] = (byte) (latitude >> 16);
        rawData[GEO_AREA_POS_LATITUDE_OFFSET + 2] = (byte) (latitude >> 8);
        rawData[GEO_AREA_POS_LATITUDE_OFFSET + 3] = (byte) latitude;
        rawData[GEO_AREA_POS_LONGITUDE_OFFSET] = (byte) (longitude >> 24);
        rawData[GEO_AREA_POS_LONGITUDE_OFFSET + 1] = (byte) (longitude >> 16);
        rawData[GEO_AREA_POS_LONGITUDE_OFFSET + 2] = (byte) (longitude >> 8);
        rawData[GEO_AREA_POS_LONGITUDE_OFFSET + 3] = (byte) longitude;
        rawData[DISTANCE_A_OFFSET] = (byte) (distanceA >> 8);
        rawData[DISTANCE_A_OFFSET + 1] = (byte) distanceA;
        rawData[DISTANCE_B_OFFSET] = (byte) (distanceB >> 8);
        rawData[DISTANCE_B_OFFSET + 1] = (byte) distanceB;
        rawData[ANGLE_OFFSET] = (byte) (angle >> 8);
        rawData[ANGLE_OFFSET + 1] = (byte) angle;
        rawData[RESERVED2_OFFSET] = (byte) (reserved2 >> 8);
        rawData[RESERVED2_OFFSET + 1] = (byte) reserved2;
        return rawData;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        final String ls = System.getProperty("line.separator");
        sb.append("[Geobroadcast (").append(length()).append(" bytes)]").append(ls);
        
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof GnGBCPacketHeader) {
            GnGBCPacketHeader that = (GnGBCPacketHeader) obj;
            return this.sequenceNumber == that.sequenceNumber
                    && this.reserved1 == that.reserved2
                    && this.source.equals(that.source)
                    && this.latitude == that.latitude
                    && this.longitude == that.longitude
                    && this.distanceA == that.distanceA
                    && this.distanceB == that.distanceB
                    && this.angle == that.angle
                    && this.reserved2 == that.reserved2;
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 1;
        hash = hash * 41 + sequenceNumber;
        hash = hash * 41 + reserved1;
        hash = hash * 41 + source.hashCode();
        hash = hash * 41 + latitude;
        hash = hash * 41 + longitude;
        hash = hash * 41 + distanceA;
        hash = hash * 41 + distanceB;
        hash = hash * 41 + angle;
        hash = hash * 41 + reserved2;
        return hash;
    }
}
