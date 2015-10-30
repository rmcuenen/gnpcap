package org.pcap4j.packet.factory;

import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnHeader;
import cuenen.raymond.gn.packet.GeoNetworkingPacket.GnPacketHeader;
import cuenen.raymond.gn.packet.factory.GnTransportTypePacketFactory;
import cuenen.raymond.gn.packet.factory.GnDataLinkTypePacketFactory;
import cuenen.raymond.gn.packet.factory.GnEtherTypePacketFactory;
import cuenen.raymond.gn.packet.factory.GnHeaderTypeFactory;
import cuenen.raymond.gn.packet.factory.GnExtendedHeaderTypeFactory;
import cuenen.raymond.gn.packet.namednumber.GnTransportType;
import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.NamedNumber;

final class PacketFactoryBinder {

    private static final PacketFactoryBinder INSTANCE = new PacketFactoryBinder();

    private final Map<Class<? extends NamedNumber<?, ?>>, PacketFactory<?, ?>> packetFactories = new HashMap<>();
    private final Map<Class<?>, PacketFactory<?, ?>> packetpPieceFactories = new HashMap<>();

    private PacketFactoryBinder() {
        packetFactories.put(DataLinkType.class, GnDataLinkTypePacketFactory.getInstance());
        packetFactories.put(EtherType.class, GnEtherTypePacketFactory.getInstance());
        packetFactories.put(GnTransportType.class, GnTransportTypePacketFactory.getInstance());
        packetpPieceFactories.put(GnHeader.class, GnHeaderTypeFactory.getInstance());
        packetpPieceFactories.put(GnPacketHeader.class, GnExtendedHeaderTypeFactory.getInstance());
    }

    public static PacketFactoryBinder getInstance() {
        return INSTANCE;
    }

    public <T, N extends NamedNumber<?, ?>> PacketFactory<T, N> getPacketFactory(
            Class<T> targetClass, Class<N> numberClass) {
        PacketFactory<?, ?> factory;
        if (Packet.class.isAssignableFrom(targetClass)) {
            factory = packetFactories.get(numberClass);
        } else {
            factory = packetpPieceFactories.get(targetClass);
        }
        return (PacketFactory<T, N>) (factory == null ? StaticUnknownPacketFactory.getInstance() : factory);
    }
}
