package cuenen.raymond.gn.packet.namednumber;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.namednumber.NamedNumber;

public final class GnTransportType extends NamedNumber<Byte, GnTransportType> {

    public static final GnTransportType ANY = new GnTransportType((byte) 0, "Unspecified");
    public static final GnTransportType BTP_A = new GnTransportType((byte) 1, "BTP-A");
    public static final GnTransportType BTP_B = new GnTransportType((byte) 2, "BTP-B");
    public static final GnTransportType IPV6 = new GnTransportType((byte) 3, "IPv6");

    private static final Map<Byte, GnTransportType> registry = new HashMap<>();

    static {
        registry.put(ANY.value(), ANY);
        registry.put(BTP_A.value(), BTP_A);
        registry.put(BTP_B.value(), BTP_B);
        registry.put(IPV6.value(), IPV6);
    }

    public GnTransportType(Byte value, String name) {
        super(value, name);
    }

    public static GnTransportType getInstance(Byte value) {
        if (registry.containsKey(value)) {
            return registry.get(value);
        } else {
            return new GnTransportType(value, "unknown");
        }
    }

    public static GnTransportType register(GnTransportType type) {
        return registry.put(type.value(), type);
    }

    @Override
    public int compareTo(GnTransportType o) {
        return value().compareTo(o.value());
    }

    @Override
    public String toString() {
        return name() + " (" + valueAsString() + ")";
    }
}
