package cuenen.raymond.gn.packet.factory;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.NamedNumber;

public abstract class AbstractGnPacketFactory<N extends NamedNumber<?, ?>> implements PacketFactory<Packet, N> {

    public static interface PacketInstantiater {

        public Packet newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException;

        public Class<? extends Packet> getTargetClass();
    }

    protected final Map<N, PacketInstantiater> instantiaters = new HashMap<>();

    @Override
    public Packet newInstance(byte[] rawData, int offset, int length, N number) {
        PacketInstantiater instantiater = instantiaters.get(number);
        if (instantiater != null) {
            try {
                return instantiater.newInstance(rawData, offset, length);
            } catch (IllegalRawDataException e) {
                return IllegalPacket.newPacket(rawData, offset, length);
            }
        }
        return newInstance(rawData, offset, length);
    }

    @Override
    public Packet newInstance(byte[] rawData, int offset, int length) {
        return UnknownPacket.newPacket(rawData, offset, length);
    }

    @Override
    public Class<? extends Packet> getTargetClass(N number) {
        final PacketInstantiater pi = instantiaters.get(number);
        return pi == null ? getTargetClass() : pi.getTargetClass();
    }

    @Override
    public Class<? extends Packet> getTargetClass() {
        return UnknownPacket.class;
    }
}
