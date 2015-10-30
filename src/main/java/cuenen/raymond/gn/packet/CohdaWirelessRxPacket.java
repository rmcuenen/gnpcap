package cuenen.raymond.gn.packet;

import java.math.BigDecimal;
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

public final class CohdaWirelessRxPacket extends AbstractPacket {

    private final CohdaWirelessRxHeader header;
    private final Packet payload;

    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param rawData
     * @param offset
     * @param length
     * @return a new CohdaWirelessRxPacket object.
     * @throws IllegalRawDataException
     */
    public static CohdaWirelessRxPacket newPacket(byte[] rawData, int offset, int length)
            throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new CohdaWirelessRxPacket(rawData, offset, length);
    }

    private CohdaWirelessRxPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        header = new CohdaWirelessRxHeader(rawData, offset, length);
        final int payloadLength = length - header.length();
        if (payloadLength > 0) {
            final int payloadOffset = offset + header.length();
            payload = PacketFactories.getFactory(Packet.class, DataLinkType.class)
                    .newInstance(rawData, payloadOffset, payloadLength, DataLinkType.EN10MB);
        } else {
            payload = null;
        }
    }

    private CohdaWirelessRxPacket(Builder builder) {
        payload = builder.payloadBuilder == null ? null : builder.payloadBuilder.build();
        header = new CohdaWirelessRxHeader(builder);
    }

    @Override
    public CohdaWirelessRxHeader getHeader() {
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
        private short rxPowerA;
        private short rxPowerB;
        private short rxNoiseA;
        private short rxNoiseB;
        private int reserved;
        private long tsf;
        private byte idlePower;
        private byte chUtil;
        private short chUtilPer;
        private byte trice;
        private int fineFreq;
        private Packet.Builder payloadBuilder;

        public Builder() {
        }

        public Builder(CohdaWirelessRxPacket packet) {
            channelNumber = packet.header.channelNumber;
            priority = packet.header.priority;
            service = packet.header.service;
            mcs = packet.header.mcs;
            rxPowerA = packet.header.rxPowerA;
            rxPowerB = packet.header.rxPowerB;
            rxNoiseA = packet.header.rxNoiseA;
            rxNoiseB = packet.header.rxNoiseB;
            reserved = packet.header.reserved;
            tsf = packet.header.tsf;
            idlePower = packet.header.idlePower;
            chUtil = packet.header.chUtil;
            chUtilPer = packet.header.chUtilPer;
            trice = packet.header.trice;
            fineFreq = packet.header.fineFreq;
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

        public Builder rxPowerA(short rxPowerA) {
            this.rxPowerA = rxPowerA;
            return this;
        }

        public Builder rxPowerB(short rxPowerB) {
            this.rxPowerB = rxPowerB;
            return this;
        }

        public Builder rxNoiseA(short rxNoiseA) {
            this.rxNoiseA = rxNoiseA;
            return this;
        }

        public Builder rxNoiseB(short rxNoiseB) {
            this.rxNoiseB = rxNoiseB;
            return this;
        }

        public Builder reserved(int reserved) {
            this.reserved = reserved;
            return this;
        }

        public Builder tsf(long tsf) {
            this.tsf = tsf;
            return this;
        }

        public Builder idlePower(byte idlePower) {
            this.idlePower = idlePower;
            return this;
        }

        public Builder chUtil(byte chUtil) {
            this.chUtil = chUtil;
            return this;
        }

        public Builder chUtilPer(short chUtilPer) {
            this.chUtilPer = chUtilPer;
            return this;
        }

        public Builder trice(byte trice) {
            this.trice = trice;
            return this;
        }

        public Builder fineFreq(int fineFreq) {
            this.fineFreq = fineFreq;
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
            return new CohdaWirelessRxPacket(this);
        }
    }

    public static final class CohdaWirelessRxHeader extends AbstractHeader {

        private static final int CHANNEL_NUMBER_OFFSET = 0;
        private static final int CHANNEL_NUMBER_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int PRIORITY_OFFSET = CHANNEL_NUMBER_OFFSET + CHANNEL_NUMBER_SIZE;
        private static final int PRIORITY_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int SERVICE_OFFSET = PRIORITY_OFFSET + PRIORITY_SIZE;
        private static final int SERVICE_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int MCS_OFFSET = SERVICE_OFFSET + SERVICE_SIZE;
        private static final int MCS_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int RX_POWER_A_OFFSET = MCS_OFFSET + MCS_SIZE;
        private static final int RX_POWER_A_SIZE = SHORT_SIZE_IN_BYTES;
        private static final int RX_POWER_B_OFFSET = RX_POWER_A_OFFSET + RX_POWER_A_SIZE;
        private static final int RX_POWER_B_SIZE = SHORT_SIZE_IN_BYTES;
        private static final int RX_NOISE_A_OFFSET = RX_POWER_B_OFFSET + RX_POWER_B_SIZE;
        private static final int RX_NOISE_A_SIZE = SHORT_SIZE_IN_BYTES;
        private static final int RX_NOISE_B_OFFSET = RX_NOISE_A_OFFSET + RX_NOISE_A_SIZE;
        private static final int RX_NOISE_B_SIZE = SHORT_SIZE_IN_BYTES;
        private static final int RESERVED_OFFSET = RX_NOISE_B_OFFSET + RX_NOISE_B_SIZE;
        private static final int RESERVED_SIZE = INT_SIZE_IN_BYTES;
        private static final int TSF_OFFSET = RESERVED_OFFSET + RESERVED_SIZE;
        private static final int TSF_SIZE = LONG_SIZE_IN_BYTES;
        private static final int IDLE_POWER_OFFSET = TSF_OFFSET + TSF_SIZE;
        private static final int IDLE_POWER_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int CH_UTIL_OFFSET = IDLE_POWER_OFFSET + IDLE_POWER_SIZE;
        private static final int CH_UTIL_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int CH_UTIL_PER_OFFSET = CH_UTIL_OFFSET + CH_UTIL_SIZE;
        private static final int CH_UTIL_PER_SIZE = SHORT_SIZE_IN_BYTES;
        private static final int TRICE_OFFSET = CH_UTIL_PER_OFFSET + CH_UTIL_PER_SIZE;
        private static final int TRICE_SIZE = BYTE_SIZE_IN_BYTES;
        private static final int FINE_FREQ_OFFSET = TRICE_OFFSET + TRICE_SIZE;
        private static final int FINE_FREQ_SIZE = INT_SIZE_IN_BYTES - TRICE_SIZE;
        private static final int COHDA_WIRELESS_RX_HEADER_SIZE = FINE_FREQ_OFFSET + FINE_FREQ_SIZE;

        private final byte channelNumber;
        private final byte priority;
        private final byte service; // NamedNumber?
        private final byte mcs; // NamedNumber?
        private final short rxPowerA;
        private final short rxPowerB;
        private final short rxNoiseA;
        private final short rxNoiseB;
        private final int reserved;
        private final long tsf;
        private final byte idlePower;
        private final byte chUtil;
        private final short chUtilPer;
        private final byte trice;
        private final int fineFreq;

        private CohdaWirelessRxHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
            if (length < COHDA_WIRELESS_RX_HEADER_SIZE) {
                throw new IllegalRawDataException("The data is too short to build a Cohda Wireless proprietary header");
            }
            channelNumber = ByteArrays.getByte(rawData, CHANNEL_NUMBER_OFFSET + offset);
            priority = ByteArrays.getByte(rawData, PRIORITY_OFFSET + offset);
            service = ByteArrays.getByte(rawData, SERVICE_OFFSET + offset);
            mcs = ByteArrays.getByte(rawData, MCS_OFFSET + offset);
            rxPowerA = ByteArrays.getShort(rawData, RX_POWER_A_OFFSET + offset, ByteOrder.LITTLE_ENDIAN);
            rxPowerB = ByteArrays.getShort(rawData, RX_POWER_B_OFFSET + offset, ByteOrder.LITTLE_ENDIAN);
            rxNoiseA = ByteArrays.getShort(rawData, RX_NOISE_A_OFFSET + offset, ByteOrder.LITTLE_ENDIAN);
            rxNoiseB = ByteArrays.getShort(rawData, RX_NOISE_B_OFFSET + offset, ByteOrder.LITTLE_ENDIAN);
            reserved = ByteArrays.getInt(rawData, RESERVED_OFFSET + offset, ByteOrder.LITTLE_ENDIAN);
            tsf = ByteArrays.getLong(rawData, TSF_OFFSET + offset, ByteOrder.LITTLE_ENDIAN);
            idlePower = ByteArrays.getByte(rawData, IDLE_POWER_OFFSET + offset);
            chUtil = ByteArrays.getByte(rawData, CH_UTIL_OFFSET + offset);
            chUtilPer = ByteArrays.getShort(rawData, CH_UTIL_PER_OFFSET + offset, ByteOrder.LITTLE_ENDIAN);
            trice = ByteArrays.getByte(rawData, TRICE_OFFSET + offset);
            fineFreq = ByteArrays.getInt(rawData, FINE_FREQ_OFFSET + offset, FINE_FREQ_SIZE, ByteOrder.LITTLE_ENDIAN);
        }

        private CohdaWirelessRxHeader(Builder builder) {
            channelNumber = builder.channelNumber;
            priority = builder.priority;
            service = builder.service;
            mcs = builder.mcs;
            rxPowerA = builder.rxPowerA;
            rxPowerB = builder.rxPowerB;
            rxNoiseA = builder.rxNoiseA;
            rxNoiseB = builder.rxNoiseB;
            reserved = builder.reserved;
            tsf = builder.tsf;
            idlePower = builder.idlePower;
            chUtil = builder.chUtil;
            chUtilPer = builder.chUtilPer;
            trice = builder.trice;
            fineFreq = builder.fineFreq;
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

        public short getRxPowerA() {
            return rxPowerA;
        }

        public short getRxPowerB() {
            return rxPowerB;
        }

        public short getRxNoiseA() {
            return rxNoiseA;
        }

        public short getRxNoiseB() {
            return rxNoiseB;
        }

        public int getReserved() {
            return reserved;
        }

        public long getTsf() {
            return tsf;
        }

        public byte getIdlePower() {
            return idlePower;
        }

        public byte getChUtil() {
            return chUtil;
        }

        public short getChUtilPer() {
            return chUtilPer;
        }

        public byte getTrice() {
            return trice;
        }

        public int getFineFreq() {
            return fineFreq;
        }

        @Override
        protected List<byte[]> getRawFields() {
            final List<byte[]> rawFields = new ArrayList<>();
            rawFields.add(ByteArrays.toByteArray(channelNumber));
            rawFields.add(ByteArrays.toByteArray(priority));
            rawFields.add(ByteArrays.toByteArray(service));
            rawFields.add(ByteArrays.toByteArray(mcs));
            rawFields.add(ByteArrays.toByteArray(rxPowerA, ByteOrder.LITTLE_ENDIAN));
            rawFields.add(ByteArrays.toByteArray(rxPowerB, ByteOrder.LITTLE_ENDIAN));
            rawFields.add(ByteArrays.toByteArray(rxNoiseA, ByteOrder.LITTLE_ENDIAN));
            rawFields.add(ByteArrays.toByteArray(rxNoiseB, ByteOrder.LITTLE_ENDIAN));
            rawFields.add(ByteArrays.toByteArray(reserved, ByteOrder.LITTLE_ENDIAN));
            rawFields.add(ByteArrays.toByteArray(tsf, ByteOrder.LITTLE_ENDIAN));
            rawFields.add(ByteArrays.toByteArray(idlePower));
            rawFields.add(ByteArrays.toByteArray(chUtil));
            rawFields.add(ByteArrays.toByteArray(chUtilPer, ByteOrder.LITTLE_ENDIAN));
            rawFields.add(ByteArrays.toByteArray(trice));
            rawFields.add(ByteArrays.toByteArray(fineFreq, 3, ByteOrder.LITTLE_ENDIAN));
            return rawFields;
        }

        @Override
        public int length() {
            return COHDA_WIRELESS_RX_HEADER_SIZE;
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
            sb.append("  RxPowerA: ").append(f.format(rxPowerA / 2.0));
            sb.append(" dB (").append(rxPowerA).append(')').append(ls);
            sb.append("  RxPowerB: ").append(f.format(rxPowerB / 2.0));
            sb.append(" dB (").append(rxPowerB).append(')').append(ls);
            sb.append("  RxNoiseA: ").append(f.format(rxNoiseA / 2.0));
            sb.append(" dB (").append(rxNoiseA).append(')').append(ls);
            sb.append("  RxNoiseB: ").append(f.format(rxNoiseB / 2.0));
            sb.append(" dB (").append(rxNoiseB).append(')').append(ls);
            sb.append("  Reserved: ").append(reserved & 0xFFFFFFFFL).append(ls);
            final long quot = (tsf >>> 1) / 5;
            final long rem = tsf - quot * 10;
            final BigDecimal dec = new BigDecimal(Long.toString(quot) + rem).divide(BigDecimal.TEN.pow(6));
            f.setMinimumFractionDigits(6);
            f.setMaximumFractionDigits(6);
            sb.append("  TSF: ").append(f.format(dec.doubleValue()));
            sb.append("s (").append(Long.toString(quot)).append(rem).append(')').append(ls);
            sb.append("  IdlePower: ").append(idlePower & 0xFF).append(ls);
            final double val = chUtilPer & 0xFFFF;
            f.setMinimumFractionDigits(1);
            f.setMaximumFractionDigits(1);
            sb.append("  Ch.Util: ").append(f.format(100.0 * (chUtil & 0xFF) / val));
            sb.append(" % (").append(chUtil & 0xFF).append(')').append(ls);
            sb.append("  Ch.Util Per: ").append(chUtilPer & 0xFFFF).append(ls);
            sb.append("  FineFreq: ").append(fineFreq & 0x00FFFFFFL).append(ls);
            sb.append("  Trice: ").append(trice & 0xFF).append(ls);
            return sb.toString();
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof CohdaWirelessRxHeader) {
                CohdaWirelessRxHeader that = (CohdaWirelessRxHeader) obj;
                return this.channelNumber == that.channelNumber
                        && this.priority == that.priority
                        && this.service == that.service
                        && this.mcs == that.mcs
                        && this.rxPowerA == that.rxPowerA
                        && this.rxPowerB == that.rxPowerB
                        && this.rxNoiseA == that.rxNoiseA
                        && this.rxNoiseB == that.rxNoiseB
                        && this.reserved == that.reserved
                        && this.tsf == that.tsf
                        && this.idlePower == that.idlePower
                        && this.chUtil == that.chUtil
                        && this.chUtilPer == that.chUtilPer
                        && this.trice == that.trice
                        && this.fineFreq == that.fineFreq;
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
            hash = hash * 41 + rxPowerA;
            hash = hash * 41 + rxPowerB;
            hash = hash * 41 + rxNoiseA;
            hash = hash * 41 + rxNoiseB;
            hash = hash * 41 + reserved;
            hash = hash * 41 + (int) (tsf ^ (tsf >>> 32));
            hash = hash * 41 + idlePower;
            hash = hash * 41 + chUtil;
            hash = hash * 41 + chUtilPer;
            hash = hash * 41 + trice;
            hash = hash * 41 + fineFreq;
            return hash;
        }
    }
}
