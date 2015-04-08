package cuenen.raymond.gn.packet;

import cuenen.raymond.gn.packet.namednumber.GnHeaderType;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.util.ByteArrays;

public final class GeoNetworkingPacket extends AbstractPacket {

    private final GeoNetworkingHeader header;
    private final Packet payload;

    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param rawData
     * @param offset
     * @param length
     * @return a new GeoNetworkingPacket object.
     * @throws IllegalRawDataException
     */
    public static GeoNetworkingPacket newPacket(byte[] rawData, int offset, int length)
            throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new GeoNetworkingPacket(rawData, offset, length);
    }

    private GeoNetworkingPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        header = new GeoNetworkingHeader(rawData, offset, length);
        final int payloadLength = length - header.length();
        if (payloadLength > 0) {
            final int payloadOffset = offset + header.length();
            payload = null; //TODO
        } else {
            payload = null;
        }
    }

    private GeoNetworkingPacket(Builder builder) {
        payload = builder.payloadBuilder == null ? null : builder.payloadBuilder.build();
        header = new GeoNetworkingHeader(builder);
    }

    @Override
    public GeoNetworkingHeader getHeader() {
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
        sb.append("[GeoNetworking Header (").append(header.length()).append(" bytes)]").append(ls);
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

        private final List<GnHeader> structure = new ArrayList<>();
        private Packet.Builder payloadBuilder;

        public Builder() {
        }

        public Builder(GeoNetworkingPacket packet) {
            structure.addAll(packet.header.structure);
            payloadBuilder = packet.payload == null ? null : packet.payload.getBuilder();
        }

        public Builder structure(List<GnHeader> structure) {
            this.structure.clear();
            this.structure.addAll(structure);
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
            return new GeoNetworkingPacket(this);
        }
    }

    public static final class GeoNetworkingHeader extends AbstractHeader {

        private final List<GnHeader> structure = new ArrayList<>();
        private final int length;

        private GeoNetworkingHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
            final GnBasicHeader basicHeader = GnBasicHeader.newInstance(rawData, offset, length);
            structure.add(basicHeader);
            int size = basicHeader.length();
            GnHeader nextHeader = PacketFactories.getFactory(GnHeader.class, GnHeaderType.class)
                    .newInstance(rawData, offset + size, length - size, basicHeader.getNextHeader());
            structure.add(nextHeader);
            size += nextHeader.length();
            this.length = size;
        }

        private GeoNetworkingHeader(Builder builder) {
            structure.addAll(builder.structure);
            int size = 0;
            for (GnHeader header : structure) {
                size += header.length();
            }
            length = size;
        }

        public List<GnHeader> getStructure() {
            return structure;
        }

        @Override
        protected List<byte[]> getRawFields() {
            final List<byte[]> rawFields = new ArrayList<>();
            for (GnHeader header : structure) {
                rawFields.add(header.rawData());
            }
            return rawFields;
        }

        @Override
        public int length() {
            return length;
        }

        @Override
        protected String buildString() {
            final StringBuilder sb = new StringBuilder();
            for (GnHeader header : structure) {
                sb.append(header);
            }
            return sb.toString();
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof GeoNetworkingHeader) {
                GeoNetworkingHeader that = (GeoNetworkingHeader) obj;
                return this.structure.equals(that.structure);
            }
            return false;
        }

        @Override
        protected int calcHashCode() {
            return 41 + structure.hashCode();
        }
    }

    public interface GnHeader extends Serializable {

        public int length();

        public byte[] rawData();
    }

    private static String toBinaryString(int value, int bits) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 1 << (bits - 1); i > 0; i /= 2) {
            if ((value & i) != 0) {
                sb.append('1');
            } else {
                sb.append('0');
            }
        }
        return sb.toString();
    }
}
