package cuenen.raymond.gn.packet.factory;

import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnHeader;
import cuenen.raymond.gn.packet.GnEmptyHeader;
import cuenen.raymond.gn.packet.GnMalformedHeader;
import cuenen.raymond.gn.packet.namednumber.GnPacketHeaderType;
import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.factory.PacketFactory;

public class GnPacketHeaderTypeFactory implements PacketFactory<GnHeader, GnPacketHeaderType> {

    private static final GnPacketHeaderTypeFactory INSTANCE = new GnPacketHeaderTypeFactory();
    private final Map<GnPacketHeaderType, Instantiater> instantiaters = new HashMap<>();

    private GnPacketHeaderTypeFactory() {
    }

    public static GnPacketHeaderTypeFactory getInstance() {
        return INSTANCE;
    }

    @Override
    public GnHeader newInstance(byte[] rawData, int offset, int length, GnPacketHeaderType number) {
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
    public GnHeader newInstance(byte[] rawData, int offset, int length) {
        return GnEmptyHeader.newInstance(rawData, offset, length);
    }

    @Override
    public Class<? extends GnHeader> getTargetClass(GnPacketHeaderType number) {
        Instantiater instantiater = instantiaters.get(number);
        return instantiater != null ? instantiater.getTargetClass() : getTargetClass();
    }

    @Override
    public Class<? extends GnHeader> getTargetClass() {
        return GnEmptyHeader.class;
    }

    private static interface Instantiater {

        public GnHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException;

        public Class<? extends GnHeader> getTargetClass();

    }
}
