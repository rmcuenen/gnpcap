package cuenen.raymond.gn.packet.namednumber;

import org.pcap4j.packet.namednumber.DataLinkType;

public final class DataLinkTypes {

    public static final DataLinkType COHDA_WIRELESS = new DataLinkType(158, "Cohda");

    static {
        DataLinkType.register(COHDA_WIRELESS);
    }

    private DataLinkTypes() {

    }
}
