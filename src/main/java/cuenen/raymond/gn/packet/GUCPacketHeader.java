package cuenen.raymond.gn.packet;

import cuenen.raymond.gn.util.LongPositionVector;
import cuenen.raymond.gn.util.ShortPositionVector;
import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnHeader;
import static cuenen.raymond.gn.util.LongPositionVector.LONG_POSITION_VECTOR_SIZE;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.*;

public final class GUCPacketHeader implements GnHeader {
    
    private static final int SN_OFFSET = 0;
    private static final int SN_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int RESERVED_OFFSET = SN_OFFSET + SN_SIZE;
    private static final int RESERVED_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int SO_PV_OFFSET = RESERVED_OFFSET + RESERVED_SIZE;
    private static final int SO_PV_SIZE = LONG_POSITION_VECTOR_SIZE;
    private static final int DE_PV_OFFSET = SO_PV_OFFSET + SO_PV_SIZE;
    private static final int DE_PV_SIZE = LONG_SIZE_IN_BYTES;
    private static final int GUC_PACKET_HEADER_SIZE = DE_PV_OFFSET + DE_PV_SIZE;
    
    private final short sequenceNumber;
    private final short reserved;
    private final LongPositionVector source;
    private final ShortPositionVector destination;
    
    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param rawData
     * @param offset
     * @param length
     * @return a new GUCPacketHeader object.
     * @throws org.pcap4j.packet.IllegalRawDataException
     */
    public static GUCPacketHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new GUCPacketHeader(rawData, offset, length);
    }

    private GUCPacketHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        if (length < GUC_PACKET_HEADER_SIZE) {
            throw new IllegalRawDataException("The data is too short to build a GUC packet header");
        }
    }
}
