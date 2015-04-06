package org.pcap4j.packet.factory;

import cuenen.raymond.gn.packet.factory.GnDataLinkTypePacketFactory;
import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.NamedNumber;

final class PacketFactoryBinder {

    private static final PacketFactoryBinder INSTANCE = new PacketFactoryBinder();

    private final Map<Class<? extends NamedNumber<?, ?>>, PacketFactory<?, ?>> packetFactories = new HashMap<>();
    private final Map<Class<?>, PacketFactory<?, ?>> packetpPieceFactories = new HashMap<>();

    private PacketFactoryBinder() {
        packetFactories.put(DataLinkType.class, GnDataLinkTypePacketFactory.getInstance());
    }

    public static PacketFactoryBinder getInstance() {
        return INSTANCE;
    }

    public <T, N extends NamedNumber<?, ?>> PacketFactory<T, N> getPacketFactory(
            Class<T> targetClass, Class<N> numberClass) {
        if (Packet.class.isAssignableFrom(targetClass)) {
            return (PacketFactory<T, N>) packetFactories.get(numberClass);
        }
        return (PacketFactory<T, N>) packetpPieceFactories.get(targetClass);
    }
}
