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
import cuenen.raymond.gn.packet.namednumber.GnPacketHeaderType;
import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.factory.PacketFactory;

public class GnPacketHeaderTypeFactory implements PacketFactory<GnPacketHeader, GnPacketHeaderType> {

    private static final GnPacketHeaderTypeFactory INSTANCE = new GnPacketHeaderTypeFactory();
    private final Map<GnPacketHeaderType, Instantiater> instantiaters = new HashMap<>();

    private GnPacketHeaderTypeFactory() {
        instantiaters.put(GnPacketHeaderType.GEOUNICAST, new Instantiater() {

            @Override
            public GnPacketHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
                return GnGUCPacketHeader.newInstance(rawData, offset, length);
            }

            @Override
            public Class<? extends GnPacketHeader> getTargetClass() {
                return GnGUCPacketHeader.class;
            }
        });
        instantiaters.put(GnPacketHeaderType.TSB_SINGLE, new Instantiater() {

            @Override
            public GnPacketHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
                return GnSHBPacketHeader.newInstance(rawData, offset, length);
            }

            @Override
            public Class<? extends GnPacketHeader> getTargetClass() {
                return GnSHBPacketHeader.class;
            }
        });
        instantiaters.put(GnPacketHeaderType.TSB_MULTI, new Instantiater() {

            @Override
            public GnPacketHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
                return GnTSBPacketHeader.newInstance(rawData, offset, length);
            }

            @Override
            public Class<? extends GnPacketHeader> getTargetClass() {
                return GnTSBPacketHeader.class;
            }
        });
        final Instantiater gbcInstantiater = new Instantiater() {

            @Override
            public GnPacketHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
                return GnGBCPacketHeader.newInstance(rawData, offset, length);
            }

            @Override
            public Class<? extends GnPacketHeader> getTargetClass() {
                return GnGBCPacketHeader.class;
            }
        };
        instantiaters.put(GnPacketHeaderType.GEOBROADCAST_CIRCLE, gbcInstantiater);
        instantiaters.put(GnPacketHeaderType.GEOBROADCAST_RECT, gbcInstantiater);
        instantiaters.put(GnPacketHeaderType.GEOBROADCAST_ELIP, gbcInstantiater);
        instantiaters.put(GnPacketHeaderType.GEOANYCAST_CIRCLE, gbcInstantiater);
        instantiaters.put(GnPacketHeaderType.GEOANYCAST_RECT, gbcInstantiater);
        instantiaters.put(GnPacketHeaderType.GEOANYCAST_ELIP, gbcInstantiater);
        instantiaters.put(GnPacketHeaderType.BEACON, new Instantiater() {

            @Override
            public GnPacketHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
                return GnBeaconPacketHeader.newInstance(rawData, offset, length);
            }

            @Override
            public Class<? extends GnPacketHeader> getTargetClass() {
                return GnBeaconPacketHeader.class;
            }
        });
        instantiaters.put(GnPacketHeaderType.LS_REQUEST, new Instantiater() {

            @Override
            public GnPacketHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
                return GnLSRequestPacketHeader.newInstance(rawData, offset, length);
            }

            @Override
            public Class<? extends GnPacketHeader> getTargetClass() {
                return GnLSRequestPacketHeader.class;
            }
        });
        instantiaters.put(GnPacketHeaderType.LS_REPLY, new Instantiater() {

            @Override
            public GnPacketHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
                return GnLSReplyPacketHeader.newInstance(rawData, offset, length);
            }

            @Override
            public Class<? extends GnPacketHeader> getTargetClass() {
                return GnLSReplyPacketHeader.class;
            }
        });
    }

    public static GnPacketHeaderTypeFactory getInstance() {
        return INSTANCE;
    }

    @Override
    public GnPacketHeader newInstance(byte[] rawData, int offset, int length, GnPacketHeaderType number) {
        try {
            Instantiater instantiater = instantiaters.get(number);
            if (instantiater != null) {
                return instantiater.newInstance(rawData, offset, length);
            }
        } catch (IllegalRawDataException e) {
            return GnMalformedHeader.newInstance(rawData, offset, length);
        }
        return newInstance(rawData, offset, length);
    }

    @Override
    public GnPacketHeader newInstance(byte[] rawData, int offset, int length) {
        return GnEmptyHeader.newInstance(rawData, offset, length);
    }

    @Override
    public Class<? extends GnPacketHeader> getTargetClass(GnPacketHeaderType number) {
        Instantiater instantiater = instantiaters.get(number);
        return instantiater != null ? instantiater.getTargetClass() : getTargetClass();
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
