package cuenen.raymond.gn.packet.factory;

import cuenen.raymond.gn.packet.CohdaWirelessPacket;
import cuenen.raymond.gn.packet.namednumber.NamedNumberTypes;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.DataLinkType;

public final class GnDataLinkTypePacketFactory extends AbstractGnPacketFactory<DataLinkType> {

    private static final GnDataLinkTypePacketFactory INSTANCE = new GnDataLinkTypePacketFactory();

    private GnDataLinkTypePacketFactory() {
        instantiaters.put(NamedNumberTypes.COHDA_WIRELESS, new PacketInstantiater() {

            @Override
            public Packet newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
                return CohdaWirelessPacket.newPacket(rawData, offset, length);
            }

            @Override
            public Class<? extends Packet> getTargetClass() {
                return CohdaWirelessPacket.class;
            }
        });
        instantiaters.put(DataLinkType.EN10MB, new PacketInstantiater() {
            @Override
            public Packet newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
                return EthernetPacket.newPacket(rawData, offset, length);
            }

            @Override
            public Class<EthernetPacket> getTargetClass() {
                return EthernetPacket.class;
            }
        });
    }

    public static GnDataLinkTypePacketFactory getInstance() {
        return INSTANCE;
    }
}
