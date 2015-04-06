package cuenen.raymond.gn.packet.factory;

import org.pcap4j.packet.namednumber.DataLinkType;

public final class GnDataLinkTypePacketFactory extends AbstractGnPacketFactory<DataLinkType> {

    private static final GnDataLinkTypePacketFactory INSTANCE = new GnDataLinkTypePacketFactory();

    private GnDataLinkTypePacketFactory() {

    }

    public static GnDataLinkTypePacketFactory getInstance() {
        return INSTANCE;
    }
}
