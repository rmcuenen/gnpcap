package cuenen.raymond.gn.util;

import java.text.NumberFormat;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.*;

public final class LongPositionVector extends ShortPositionVector {

    private static final int PAI_S_OFFSET = ShortPositionVector.SIZE_IN_BYTES;
    private static final int PAI_S_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int H_OFFSET = PAI_S_OFFSET + PAI_S_SIZE;
    private static final int H_SIZE = SHORT_SIZE_IN_BYTES;
    public static final int SIZE_IN_BYTES = H_OFFSET + H_SIZE;

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
        super(rawData, offset, length);
        if (length < SIZE_IN_BYTES) {
            throw new IllegalRawDataException("The data is too short to build a Long Position Vector");
        }
        final short val = ByteArrays.getShort(rawData, PAI_S_OFFSET + offset);
        System.out.println(Integer.toHexString(val));
        pai = (byte) ((val & 0x8000) >> 15);
        speed = (short) (val & 0x7FFF);
        heading = ByteArrays.getShort(rawData, H_OFFSET + offset);
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
    public void writeTo(byte[] rawData, int offset) {
        ByteArrays.validateBounds(rawData, offset, SIZE_IN_BYTES);
        super.writeTo(rawData, offset);
        final short ps = (short) ((pai << 15) | speed);
        rawData[PAI_S_OFFSET] = (byte) (ps << 8);
        rawData[PAI_S_OFFSET + 1] = (byte) ps;
        rawData[H_OFFSET] = (byte) (heading << 8);
        rawData[H_OFFSET + 1] = (byte) heading;
    }

    @Override
    public String buildString(String prefix) {
        final StringBuilder sb = new StringBuilder();
        final String ls = System.getProperty("line.separator");
        sb.append(super.buildString(prefix));
        sb.append(prefix).append(BitValues.toBinaryString(pai, 1)).append("............... = PAI: ");
        sb.append(pai).append(ls);
        final NumberFormat f = NumberFormat.getNumberInstance();
        f.setGroupingUsed(false);
        f.setMinimumIntegerDigits(1);
        f.setMinimumFractionDigits(2);
        f.setMaximumFractionDigits(2);
        final double ms = speed * 0.01;
        final double kmh = ms * 3.6;
        sb.append(prefix).append("Speed: ").append(f.format(ms)).append(" m/s | ");
        sb.append(f.format(kmh)).append(" km/h (").append(speed).append(')').append(ls);
        final double h = (heading & 0xFFFF) * 0.1;
        f.setMinimumFractionDigits(1);
        f.setMaximumFractionDigits(1);
        sb.append(prefix).append("Heading: ").append(f.format(h)).append("\u00b0 (");
        sb.append(heading & 0xFFFF).append(')').append(ls);
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof LongPositionVector) {
            LongPositionVector that = (LongPositionVector) obj;
            return super.equals(obj)
                    && this.pai == that.pai
                    && this.speed == that.speed
                    && this.heading == that.heading;
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = super.hashCode();
        hash = hash * 41 + pai;
        hash = hash * 41 + speed;
        hash = hash * 41 + heading;
        return hash;
    }
}
