/*
 * $Revision$
 *
 * Copyright (c) 2008-2015 Vialis BV 
 */
package cuenen.raymond.gn.packet;

import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnHeader;
import java.util.Arrays;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.*;

public class GnSecureHeader implements GnHeader {

    private static final int PROTOCOL_VERSION_OFFSET = 0;
    private static final int PROTOCOL_VERSION_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int SECURITY_PROFILE_OFFSET = PROTOCOL_VERSION_OFFSET + PROTOCOL_VERSION_SIZE;
    private static final int SECURITY_PROFILE_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int HEADER_LENGTH_OFFSET = SECURITY_PROFILE_OFFSET + SECURITY_PROFILE_SIZE;
    private static final int HEADER_LENGTH_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int HEADER_FIELDS_OFFSET = HEADER_LENGTH_OFFSET + HEADER_LENGTH_SIZE;
    private static final int PAYLOAD_LENGTH_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int PAYLOAD_TYPE_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int PAYLOAD_DATA_LENGTH_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int SECURE_HEADER_MIN_SIZE = HEADER_FIELDS_OFFSET + PAYLOAD_LENGTH_SIZE
            + PAYLOAD_TYPE_SIZE + PAYLOAD_DATA_LENGTH_SIZE;

    private final byte protocolVersion;
    private final byte securityProfile; // NamedNumber?
    private final byte headerLength;
    private final byte[] headerFields;
    private final short payloadLength;
    private final byte payloadType; // NamedNumber?
    private final short payloadDataLength;

    /**
     * A static factory method. This method validates the arguments by
     * {@link ByteArrays#validateBounds(byte[], int, int)}, which may throw
     * exceptions undocumented here.
     *
     * @param rawData
     * @param offset
     * @param length
     * @return a new GnCommonHeader object.
     * @throws org.pcap4j.packet.IllegalRawDataException
     */
    public static GnSecureHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new GnSecureHeader(rawData, offset, length);
    }

    private GnSecureHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        if (length < SECURE_HEADER_MIN_SIZE) {
            throw new IllegalRawDataException("The data is too short to build a Secure header");
        }
        protocolVersion = ByteArrays.getByte(rawData, PROTOCOL_VERSION_OFFSET + offset);
        securityProfile = ByteArrays.getByte(rawData, SECURITY_PROFILE_OFFSET + offset);
        headerLength = ByteArrays.getByte(rawData, HEADER_LENGTH_OFFSET + offset);
        int headers = headerLength & 0xFF;
        headerFields = ByteArrays.getSubArray(rawData, HEADER_FIELDS_OFFSET + offset, headers);
        payloadLength = ByteArrays.getShort(rawData, HEADER_FIELDS_OFFSET + headers + offset);
        payloadType = ByteArrays.getByte(rawData, HEADER_FIELDS_OFFSET + PAYLOAD_LENGTH_SIZE
                + headers + offset);
        payloadDataLength = ByteArrays.getShort(rawData, HEADER_FIELDS_OFFSET
                + PAYLOAD_LENGTH_SIZE + PAYLOAD_TYPE_SIZE + headers + offset);
    }

    public byte getProtocolVersion() {
        return protocolVersion;
    }

    public byte getSecurityProfile() {
        return securityProfile;
    }

    public byte getHeaderLength() {
        return headerLength;
    }

    public byte[] getHeaderFields() {
        return headerFields;
    }

    public short getPayloadLength() {
        return payloadLength;
    }

    public byte getPayloadType() {
        return payloadType;
    }

    public short getPayloadDataLength() {
        return payloadDataLength;
    }

    @Override
    public int length() {
        return SECURE_HEADER_MIN_SIZE + headerFields.length;
    }

    @Override
    public byte[] rawData() {
        final byte[] rawData = new byte[SECURE_HEADER_MIN_SIZE + headerFields.length];
        rawData[PROTOCOL_VERSION_OFFSET] = protocolVersion;
        rawData[SECURITY_PROFILE_OFFSET] = securityProfile;
        rawData[HEADER_LENGTH_OFFSET] = headerLength;
        System.arraycopy(headerFields, 0, rawData, HEADER_FIELDS_OFFSET, headerFields.length);
        rawData[HEADER_FIELDS_OFFSET + headerFields.length] = (byte) (payloadLength >> 8);
        rawData[HEADER_FIELDS_OFFSET + headerFields.length + 1] = (byte) payloadLength;
        rawData[HEADER_FIELDS_OFFSET + PAYLOAD_LENGTH_SIZE + headerFields.length] = payloadType;
        rawData[HEADER_FIELDS_OFFSET + PAYLOAD_LENGTH_SIZE
                + PAYLOAD_TYPE_SIZE + headerFields.length] = (byte) (payloadDataLength >> 8);
        rawData[HEADER_FIELDS_OFFSET + PAYLOAD_LENGTH_SIZE
                + PAYLOAD_TYPE_SIZE + headerFields.length + 1] = (byte) payloadDataLength;
        return rawData;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        final String ls = System.getProperty("line.separator");
        sb.append("[Secure Header (").append(length()).append(" bytes)]").append(ls);
        sb.append("  Version: ").append(protocolVersion & 0xFF).append(ls);
        sb.append("  Profile: ").append(securityProfile & 0xFF).append(ls); // NamedNumber?
        sb.append("  Header Length: ").append(headerLength & 0xFF).append(ls);
        sb.append("  Header Fields: ").append(ByteArrays.toHexString(headerFields, "")).append(ls); //TODO
        sb.append("  Payload Length: ").append(payloadLength & 0x0FFF).append(ls);
        sb.append("  Payload Type: ").append(payloadType & 0xFF).append(ls); // NamedNumber?
        sb.append("  Payload Data Length: ").append(payloadLength & 0x0FFF).append(ls);
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof GnSecureHeader) {
            GnSecureHeader that = (GnSecureHeader) obj;
            return this.protocolVersion == that.protocolVersion
                    && this.securityProfile == that.securityProfile
                    && this.headerLength == that.headerLength
                    && Arrays.equals(this.headerFields, that.headerFields)
                    && this.payloadLength == that.payloadLength
                    && this.payloadType == that.payloadType
                    && this.payloadDataLength == that.payloadDataLength;
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 1;
        hash = hash * 41 + protocolVersion;
        hash = hash * 41 + securityProfile;
        hash = hash * 41 + headerLength;
        hash = hash * 41 + Arrays.hashCode(headerFields);
        hash = hash * 41 + payloadLength;
        hash = hash * 41 + payloadType;
        hash = hash * 41 + payloadDataLength;
        return hash;
    }
}
