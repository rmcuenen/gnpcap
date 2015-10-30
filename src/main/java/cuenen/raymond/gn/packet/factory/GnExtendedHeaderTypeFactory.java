package cuenen.raymond.gn.packet.factory;

import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnPacketHeader;
import cuenen.raymond.gn.packet.GnBeaconPacketHeader;
import cuenen.raymond.gn.packet.GnEmptyHeader;
import cuenen.raymond.gn.packet.GnGBCPacketHeader;
import cuenen.raymond.gn.packet.GnGUCPacketHeader;
import cuenen.raymond.gn.packet.GnLSReplyPacketHeader;
import cuenen.raymond.gn.packet.GnLSRequestPacketHeader;
import cuenen.raymond.gn.packet.GnMalformedHeader;
import cuenen.raymond.gn.packet.GnSHBPacketHeader;
import cuenen.raymond.gn.packet.GnTSBPacketHeader;
import cuenen.raymond.gn.packet.namednumber.GnExtendedHeaderType;
import cuenen.raymond.gn.packet.namednumber.GnPacketHeaderSubtype;
import cuenen.raymond.gn.packet.namednumber.GnPacketHeaderType;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.factory.PacketFactory;

public class GnExtendedHeaderTypeFactory implements PacketFactory<GnPacketHeader, GnExtendedHeaderType> {

    private static final GnExtendedHeaderTypeFactory INSTANCE = new GnExtendedHeaderTypeFactory();

    private GnExtendedHeaderTypeFactory() {

    }

    public static GnExtendedHeaderTypeFactory getInstance() {
        return INSTANCE;
    }

    @Override
    public GnPacketHeader newInstance(byte[] rawData, int offset, int length, GnExtendedHeaderType number) {
        final GnPacketHeaderType headerType = number.getHeaderType();
        try {
            if (headerType.equals(GnPacketHeaderType.BEACON)) {
                return GnBeaconPacketHeader.newInstance(rawData, offset, length);
            } else if (headerType.equals(GnPacketHeaderType.GEOANYCAST)) {
                return GnGUCPacketHeader.newInstance(rawData, offset, length);
            } else if (headerType.equals(GnPacketHeaderType.GEOANYCAST)
                    || headerType.equals(GnPacketHeaderType.GEOBROADCAST)) {
                return GnGBCPacketHeader.newInstance(rawData, offset, length);
            } else if (headerType.equals(GnPacketHeaderType.TSB)) {
                if (number.getHeaderSubtype().equals(GnPacketHeaderSubtype.SINGLE_HOP)) {
                    return GnSHBPacketHeader.newInstance(rawData, offset, length);
                }
                return GnTSBPacketHeader.newInstance(rawData, offset, length);
            } else if (headerType.equals(GnPacketHeaderType.LS)) {
                final GnPacketHeaderSubtype subtype = number.getHeaderSubtype();
                if (subtype.equals(GnPacketHeaderSubtype.REQUEST)) {
                    return GnLSRequestPacketHeader.newInstance(rawData, offset, length);
                } else if (subtype.equals(GnPacketHeaderSubtype.REPLY)) {
                    return GnLSReplyPacketHeader.newInstance(rawData, offset, length);
                }
            }
        } catch (IllegalRawDataException ex) {
            return GnMalformedHeader.newInstance(rawData, offset, length);
        }
        return newInstance(rawData, offset, length);
    }

    @Override
    public GnPacketHeader newInstance(byte[] rawData, int offset, int length) {
        return GnEmptyHeader.newInstance(rawData, offset, length);
    }

    @Override
    public Class<? extends GnPacketHeader> getTargetClass(GnExtendedHeaderType number) {
        final GnPacketHeaderType headerType = number.getHeaderType();
        if (headerType.equals(GnPacketHeaderType.BEACON)) {
            return GnBeaconPacketHeader.class;
        } else if (headerType.equals(GnPacketHeaderType.GEOANYCAST)) {
            return GnGUCPacketHeader.class;
        } else if (headerType.equals(GnPacketHeaderType.GEOANYCAST)
                || headerType.equals(GnPacketHeaderType.GEOBROADCAST)) {
            return GnGBCPacketHeader.class;
        } else if (headerType.equals(GnPacketHeaderType.TSB)) {
            if (number.getHeaderSubtype().equals(GnPacketHeaderSubtype.SINGLE_HOP)) {
                return GnSHBPacketHeader.class;
            }
            return GnTSBPacketHeader.class;
        } else if (headerType.equals(GnPacketHeaderType.LS)) {
            final GnPacketHeaderSubtype subtype = number.getHeaderSubtype();
            if (subtype.equals(GnPacketHeaderSubtype.REQUEST)) {
                return GnLSRequestPacketHeader.class;
            } else if (subtype.equals(GnPacketHeaderSubtype.REPLY)) {
                return GnLSReplyPacketHeader.class;
            }
        }
        return getTargetClass();
    }

    @Override
    public Class<? extends GnPacketHeader> getTargetClass() {
        return GnEmptyHeader.class;
    }

    private static interface Instantiater {

        public GnPacketHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException;

        public Class<? extends GnPacketHeader> getTargetClass();

    }
}
