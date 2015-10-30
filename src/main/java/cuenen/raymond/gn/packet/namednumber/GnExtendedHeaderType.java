package cuenen.raymond.gn.packet.namednumber;

import org.pcap4j.packet.namednumber.NamedNumber;

public final class GnExtendedHeaderType extends NamedNumber<Byte, GnExtendedHeaderType> {

    private final GnPacketHeaderType headerType;
    private final GnPacketHeaderSubtype headerSubtype;

    public static GnExtendedHeaderType newInstance(GnPacketHeaderType headerType, GnPacketHeaderSubtype headerSubtype) {
        return new GnExtendedHeaderType(headerType, headerSubtype);
    }

    public GnExtendedHeaderType(GnPacketHeaderType headerType, GnPacketHeaderSubtype headerSubtype) {
        super((byte) ((headerType.value() << 4) | headerSubtype.value()), headerType.name() + "/" + headerSubtype.name());
        this.headerType = headerType;
        this.headerSubtype = headerSubtype;
    }

    public GnPacketHeaderType getHeaderType() {
        return headerType;
    }

    public GnPacketHeaderSubtype getHeaderSubtype() {
        return headerSubtype;
    }

    @Override
    public int compareTo(GnExtendedHeaderType o) {
        return value().compareTo(o.value());
    }
}
