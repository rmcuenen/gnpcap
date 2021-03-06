package cuenen.raymond.gn.packet.namednumber;

import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;

public final class NamedNumberTypes {

    public static final DataLinkType COHDA_WIRELESS_TX = new DataLinkType(157, "Cohda");
    public static final DataLinkType COHDA_WIRELESS_RX = new DataLinkType(158, "Cohda");
    public static final EtherType ETSI_TC_ITS = new EtherType((short) 0x8947, "ETSI TC-ITS");

    static {
        DataLinkType.register(COHDA_WIRELESS_TX);
        DataLinkType.register(COHDA_WIRELESS_RX);
        EtherType.register(ETSI_TC_ITS);
    }

    private NamedNumberTypes() {

    }
}
