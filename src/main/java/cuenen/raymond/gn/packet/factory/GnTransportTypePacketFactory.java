package cuenen.raymond.gn.packet.factory;

import cuenen.raymond.gn.packet.BtpPacket;
import cuenen.raymond.gn.packet.namednumber.GnTransportType;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;

public class GnTransportTypePacketFactory extends AbstractGnPacketFactory<GnTransportType> {

    private static final GnTransportTypePacketFactory INSTANCE = new GnTransportTypePacketFactory();

    private GnTransportTypePacketFactory() {
        instantiaters.put(GnTransportType.BTP_A, new PacketInstantiater() {

            @Override
            public Packet newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
                return BtpPacket.newPacket(GnTransportType.BTP_A, rawData, offset, length);
            }

            @Override
            public Class<? extends Packet> getTargetClass() {
                return BtpPacket.class;
            }
        });
        instantiaters.put(GnTransportType.BTP_B, new PacketInstantiater() {

            @Override
            public Packet newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
                return BtpPacket.newPacket(GnTransportType.BTP_B, rawData, offset, length);
            }

            @Override
            public Class<? extends Packet> getTargetClass() {
                return BtpPacket.class;
            }
        });
    }

    public static GnTransportTypePacketFactory getInstance() {
        return INSTANCE;
    }
}
