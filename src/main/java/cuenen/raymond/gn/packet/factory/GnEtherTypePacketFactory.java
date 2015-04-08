package cuenen.raymond.gn.packet.factory;

import cuenen.raymond.gn.packet.GeoNetworkingPacket;
import cuenen.raymond.gn.packet.namednumber.NamedNumberTypes;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.EtherType;

public final class GnEtherTypePacketFactory extends AbstractGnPacketFactory<EtherType> {

    private static final GnEtherTypePacketFactory INSTANCE = new GnEtherTypePacketFactory();

    private GnEtherTypePacketFactory() {
        instantiaters.put(NamedNumberTypes.ETSI_TC_ITS, new PacketInstantiater() {

            @Override
            public Packet newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
                return GeoNetworkingPacket.newPacket(rawData, offset, length);
            }

            @Override
            public Class<? extends Packet> getTargetClass() {
                return GeoNetworkingPacket.class;
            }
        });
    }

    public static GnEtherTypePacketFactory getInstance() {
        return INSTANCE;
    }
}
