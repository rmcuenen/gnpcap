package cuenen.raymond.gn.packet.factory;

import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnHeader;
import cuenen.raymond.gn.packet.GnCommonHeader;
import cuenen.raymond.gn.packet.GnEmptyHeader;
import cuenen.raymond.gn.packet.GnMalformedHeader;
import cuenen.raymond.gn.packet.namednumber.GnHeaderType;
import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.factory.PacketFactory;

public final class GnHeaderTypeFactory implements PacketFactory<GnHeader, GnHeaderType> {

    private static final GnHeaderTypeFactory INSTANCE = new GnHeaderTypeFactory();
    private final Map<GnHeaderType, Instantiater> instantiaters = new HashMap<>();

    private GnHeaderTypeFactory() {
        instantiaters.put(GnHeaderType.COMMON_HEADER, new Instantiater() {

            @Override
            public GnHeader newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
                return GnCommonHeader.newInstance(rawData, offset, length);
            }

            @Override
            public Class<? extends GnHeader> getTargetClass() {
                return GnCommonHeader.class;
            }
        });
    }

    public static GnHeaderTypeFactory getInstance() {
        return INSTANCE;
    }

    @Override
    public GnHeader newInstance(byte[] rawData, int offset, int length, GnHeaderType number) {
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
    public Class<? extends GnHeader> getTargetClass(GnHeaderType number) {
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
