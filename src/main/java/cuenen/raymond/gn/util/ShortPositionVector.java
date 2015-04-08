package cuenen.raymond.gn.util;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;

public final class ShortPositionVector {

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

    private ShortPositionVector(byte[] rawData, int offset, int length) throws IllegalRawDataException {

    }
}
