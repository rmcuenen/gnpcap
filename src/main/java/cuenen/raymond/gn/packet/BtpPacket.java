package cuenen.raymond.gn.packet;

import cuenen.raymond.gn.packet.namednumber.GnTransportType;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

public final class BtpPacket extends AbstractPacket {

    private static final int DESTINATION_PORT_OFFSET = 0;
    private static final int DESTINATION_PORT_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int PORT_INFO_OFFSET = DESTINATION_PORT_OFFSET + DESTINATION_PORT_SIZE;
    private static final int PORT_INFO_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int BTP_HEADER_SIZE = PORT_INFO_OFFSET + PORT_INFO_SIZE;

    private final BtpHeader header;
    private final Packet payload;

    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param type
     * @param rawData
     * @param offset
     * @param length
     * @return a new GeoNetworkingPacket object.
     * @throws IllegalRawDataException
     */
    public static BtpPacket newPacket(GnTransportType type, byte[] rawData, int offset, int length)
            throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new BtpPacket(type, rawData, offset, length);
    }

    private BtpPacket(GnTransportType type, byte[] rawData, int offset, int length) throws IllegalRawDataException {
        header = new BtpHeader(type, rawData, offset, length);
        final int payloadLength = length - header.length();
        if (payloadLength > 0) {
            final int payloadOffset = offset + header.length();
            payload = null; //TODO
        } else {
            payload = null;
        }
    }

    private BtpPacket(Builder builder) {
        payload = builder.payloadBuilder == null ? null : builder.payloadBuilder.build();
        header = new BtpHeader(builder);
    }

    @Override
    public BtpHeader getHeader() {
        return header;
    }

    @Override
    public Packet getPayload() {
        return payload;
    }

    @Override
    protected String buildString() {
        final StringBuilder sb = new StringBuilder();
        final String ls = System.getProperty("line.separator");
        sb.append("[Basic Transport Protocol (").append(header.length()).append(" bytes)]").append(ls);
        sb.append(header);
        if (payload != null) {
            sb.append(payload);
        }
        return sb.toString();
    }

    @Override
    public Builder getBuilder() {
        return new Builder(this);
    }

    public static final class Builder extends AbstractBuilder {

        private GnTransportType type;
        private short destinationPort;
        private short portInfo;
        private Packet.Builder payloadBuilder;

        public Builder() {
        }

        public Builder(BtpPacket packet) {
            type = packet.header.type;
            destinationPort = packet.header.destinationPort;
            portInfo = packet.header.portInfo;
            payloadBuilder = packet.payload == null ? null : packet.payload.getBuilder();
        }

        public Builder type(GnTransportType type) {
            this.type = type;
            return this;
        }

        public Builder destinationPort(short destinationPort) {
            this.destinationPort = destinationPort;
            return this;
        }

        public Builder portInfo(short portInfo) {
            this.portInfo = portInfo;
            return this;
        }

        @Override
        public Builder payloadBuilder(Packet.Builder payloadBuilder) {
            this.payloadBuilder = payloadBuilder;
            return this;
        }

        @Override
        public Packet.Builder getPayloadBuilder() {
            return payloadBuilder;
        }

        @Override
        public Packet build() {
            return new BtpPacket(this);
        }
    }

    public static final class BtpHeader extends AbstractHeader {

        private final GnTransportType type;
        private final short destinationPort;
        private final short portInfo;

        private BtpHeader(GnTransportType type, byte[] rawData, int offset, int length) throws IllegalRawDataException {
            if (length < BTP_HEADER_SIZE) {
                throw new IllegalRawDataException("The data is too short to build a BTP header");
            }
            this.type = type;
            destinationPort = ByteArrays.getShort(rawData, DESTINATION_PORT_OFFSET + offset);
            portInfo = ByteArrays.getByte(rawData, PORT_INFO_OFFSET + offset);
        }

        private BtpHeader(Builder builder) {
            type = builder.type;
            destinationPort = builder.destinationPort;
            portInfo = builder.portInfo;
        }

        public short getDestinationPort() {
            return destinationPort;
        }

        public short getPortInfo() {
            return portInfo;
        }

        @Override
        public int length() {
            return BTP_HEADER_SIZE;
        }

        @Override
        protected List<byte[]> getRawFields() {
            final List<byte[]> rawFields = new ArrayList<>();
            rawFields.add(ByteArrays.toByteArray(destinationPort));
            rawFields.add(ByteArrays.toByteArray(portInfo));
            return rawFields;
        }

        @Override
        protected String buildString() {
            final StringBuilder sb = new StringBuilder();
            final String ls = System.getProperty("line.separator");
            sb.append("  Destination Port: ").append(destinationPort).append(ls);
            if (type.equals(GnTransportType.BTP_A)) {
                sb.append("  Source Port: ").append(portInfo).append(ls);
            } else if (type.equals(GnTransportType.BTP_B)) {
                sb.append("  Destination Port Info: ").append(portInfo).append(ls);
            }
            return sb.toString();
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof BtpHeader) {
                BtpHeader that = (BtpHeader) obj;
                return this.type == that.type
                        && this.destinationPort == that.destinationPort
                        && this.portInfo == that.portInfo;
            }
            return false;
        }

        @Override
        protected int calcHashCode() {
            return 41 * (41 * (41 + type.hashCode()) + destinationPort) + portInfo;
        }

    }

}
