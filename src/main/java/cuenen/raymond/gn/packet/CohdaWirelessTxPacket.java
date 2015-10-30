package cuenen.raymond.gn.packet;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteOrder;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.*;

public final class CohdaWirelessTxPacket extends AbstractPacket {

    private final CohdaWirelessTxHeader header;
    private final Packet payload;

    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param rawData
     * @param offset
     * @param length
     * @return a new CohdaWirelessTxPacket object.
     * @throws IllegalRawDataException
     */
    public static CohdaWirelessTxPacket newPacket(byte[] rawData, int offset, int length)
            throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new CohdaWirelessTxPacket(rawData, offset, length);
    }

    private CohdaWirelessTxPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        header = new CohdaWirelessTxHeader(rawData, offset, length);
        final int payloadLength = length - header.length();
        if (payloadLength > 0) {
            final int payloadOffset = offset + header.length();
            payload = PacketFactories.getFactory(Packet.class, DataLinkType.class)
                    .newInstance(rawData, payloadOffset, payloadLength, DataLinkType.EN10MB);
        } else {
            payload = null;
        }
    }

    private CohdaWirelessTxPacket(Builder builder) {
        payload = builder.payloadBuilder == null ? null : builder.payloadBuilder.build();
        header = new CohdaWirelessTxHeader(builder);
    }

    @Override
    public CohdaWirelessTxHeader getHeader() {
        return header;
    }

    @Override
    public Packet getPayload() {
        return payload;
    }

    @Override
    protected String buildString() {
        final StringBuilder sb = new StringBuilder();
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

        private byte channelNumber;
        private byte priority;
        private byte service; // NamedNumber?
        private byte mcs; // NamedNumber?
        private short manPower;
        private byte antenna; // NamedNumber?
        private long expiry;

        private Packet.Builder payloadBuilder;

        public Builder() {
        }

        public Builder(CohdaWirelessTxPacket packet) {
            channelNumber = packet.header.channelNumber;
            priority = packet.header.priority;
            service = packet.header.service;
            mcs = packet.header.mcs;
            manPower = packet.header.manPower;
            antenna = packet.header.antenna;
            expiry = packet.header.expiry;
            payloadBuilder = packet.payload == null ? null : packet.payload.getBuilder();
        }

        public Builder channelNumber(byte channelNumber) {
            this.channelNumber = channelNumber;
            return this;
        }

        public Builder priority(byte priority) {
            this.priority = priority;
            return this;
        }

        public Builder service(byte service) {
            this.service = service;
            return this;
        }

        public Builder mcs(byte mcs) {
            this.mcs = mcs;
            return this;
        }

        public Builder manPower(short manPower) {
            this.manPower = manPower;
            return this;
        }

        public Builder antenna(byte antenna) {
            this.antenna = antenna;
            return this;
        }

        public Builder expiry(long expiry) {
            this.expiry = expiry;
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
            return new CohdaWirelessTxPacket(this);
        }
    }

    public static final class CohdaWirelessTxHeader extends AbstractHeader {

        private static final int CHANNEL_NUMBER_OFFSET = 0;
        private static final int CHANNEL_NUMBER_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int PRIORITY_OFFSET = CHANNEL_NUMBER_OFFSET + CHANNEL_NUMBER_SIZE;
        private static final int PRIORITY_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int SERVICE_OFFSET = PRIORITY_OFFSET + PRIORITY_SIZE;
        private static final int SERVICE_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int MCS_OFFSET = SERVICE_OFFSET + SERVICE_SIZE;
        private static final int MCS_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int MAN_POWER_OFFSET = MCS_OFFSET + MCS_SIZE + 1;
        private static final int MAN_POWER_SIZE = SHORT_SIZE_IN_BYTES;
        private static final int ANTENNA_OFFSET = MAN_POWER_OFFSET + MAN_POWER_SIZE;
        private static final int ANTENNA_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int EXPIRY_OFFSET = ANTENNA_OFFSET + ANTENNA_SIZE;
        private static final int EXPIRY_SIZE = LONG_SIZE_IN_BYTES;
        private static final int COHDA_WIRELESS_TX_HEADER_SIZE = EXPIRY_OFFSET + EXPIRY_SIZE;

        private final byte channelNumber;
        private final byte priority;
        private final byte service; // NamedNumber?
        private final byte mcs; // NamedNumber?
        private final short manPower;
        private final byte antenna; // NamedNumber?
        private final long expiry;

        private CohdaWirelessTxHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
            if (length < COHDA_WIRELESS_TX_HEADER_SIZE) {
                throw new IllegalRawDataException("The data is too short to build a Cohda Wireless proprietary header");
            }
            channelNumber = ByteArrays.getByte(rawData, CHANNEL_NUMBER_OFFSET + offset);
            priority = ByteArrays.getByte(rawData, PRIORITY_OFFSET + offset);
            service = ByteArrays.getByte(rawData, SERVICE_OFFSET + offset);
            mcs = ByteArrays.getByte(rawData, MCS_OFFSET + offset);
            manPower = ByteArrays.getShort(rawData, MAN_POWER_OFFSET + offset, ByteOrder.LITTLE_ENDIAN);
            antenna = ByteArrays.getByte(rawData, ANTENNA_OFFSET + offset);
            expiry = ByteArrays.getLong(rawData, EXPIRY_OFFSET + offset, ByteOrder.LITTLE_ENDIAN);
        }

        private CohdaWirelessTxHeader(Builder builder) {
            channelNumber = builder.channelNumber;
            priority = builder.priority;
            service = builder.service;
            mcs = builder.mcs;
            manPower = builder.manPower;
            antenna = builder.antenna;
            expiry = builder.expiry;
        }

        public byte getChannelNumber() {
            return channelNumber;
        }

        public byte getPriority() {
            return priority;
        }

        public byte getService() {
            return service;
        }

        public byte getMcs() {
            return mcs;
        }

        public short getManPower() {
            return manPower;
        }

        public byte getAntenna() {
            return antenna;
        }

        public long getExpery() {
            return expiry;
        }

        @Override
        protected List<byte[]> getRawFields() {
            final List<byte[]> rawFields = new ArrayList<>();
            rawFields.add(ByteArrays.toByteArray(channelNumber));
            rawFields.add(ByteArrays.toByteArray(priority));
            rawFields.add(ByteArrays.toByteArray(service));
            rawFields.add(ByteArrays.toByteArray(mcs));
            rawFields.add(ByteArrays.toByteArray(manPower, ByteOrder.LITTLE_ENDIAN));
            rawFields.add(ByteArrays.toByteArray(antenna));
            rawFields.add(ByteArrays.toByteArray(expiry, ByteOrder.LITTLE_ENDIAN));
            return rawFields;
        }

        @Override
        public int length() {
            return COHDA_WIRELESS_TX_HEADER_SIZE;
        }

        @Override
        protected String buildString() {
            final StringBuilder sb = new StringBuilder();
            final String ls = System.getProperty("line.separator");
            sb.append("[Cohda Header (").append(length()).append(" bytes)]").append(ls);
            sb.append("  ChannelNumber: ").append(channelNumber & 0xFF).append(ls);
            sb.append("  Priority: ").append(priority & 0xFF).append(ls);
            sb.append("  Service: ").append(service & 0xFF).append(ls); // NamedNumber?
            sb.append("  MCS: ").append(mcs & 0xFF).append(ls); // NamedNumber?
            final NumberFormat f = NumberFormat.getNumberInstance();
            f.setGroupingUsed(false);
            f.setMinimumIntegerDigits(1);
            f.setMinimumFractionDigits(1);
            f.setMaximumFractionDigits(1);
            sb.append("  ManPower: ").append(f.format(manPower / 2.0));
            sb.append(" dB (").append(manPower).append(')').append(ls);
            sb.append("  Antenna: ").append(antenna & 0xFF).append(ls); // NamedNumber?
            final BigDecimal expVal = new BigDecimal(new BigInteger(Long.toHexString(expiry), 16));
            final BigDecimal exp = expVal.divide(new BigDecimal("1000000"));
            sb.append("  Expiry: ").append(exp.equals(BigDecimal.ZERO)
                    ? "No expiry (" : exp.toString() + "s (").append(expVal).append(')').append(ls);
            return sb.toString();
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof CohdaWirelessTxHeader) {
                CohdaWirelessTxHeader that = (CohdaWirelessTxHeader) obj;
                return this.channelNumber == that.channelNumber
                        && this.priority == that.priority
                        && this.service == that.service
                        && this.mcs == that.mcs
                        && this.manPower == that.manPower
                        && this.antenna == that.antenna
                        && this.expiry == that.expiry;
            }
            return false;
        }

        @Override
        protected int calcHashCode() {
            int hash = 1;
            hash = hash * 41 + channelNumber;
            hash = hash * 41 + priority;
            hash = hash * 41 + service;
            hash = hash * 41 + mcs;
            hash = hash * 41 + manPower;
            hash = hash * 41 + antenna;
            hash = hash * 41 + (int) (expiry ^ (expiry >>> 32));
            return hash;
        }
    }
}
