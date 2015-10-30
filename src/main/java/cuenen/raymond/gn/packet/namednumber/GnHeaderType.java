package cuenen.raymond.gn.packet.namednumber;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.namednumber.NamedNumber;

public final class GnHeaderType extends NamedNumber<Byte, GnHeaderType> {

    public static final GnHeaderType ANY = new GnHeaderType((byte) 0, "Any");
    public static final GnHeaderType COMMON_HEADER = new GnHeaderType((byte) 1, "Common");
    public static final GnHeaderType SECURE_HEADER = new GnHeaderType((byte) 2, "Secured");

    private static final Map<Byte, GnHeaderType> registry = new HashMap<>();

    static {
        registry.put(ANY.value(), ANY);
        registry.put(COMMON_HEADER.value(), COMMON_HEADER);
        registry.put(SECURE_HEADER.value(), SECURE_HEADER);
    }

    public GnHeaderType(Byte value, String name) {
        super(value, name);
    }

    public static GnHeaderType getInstance(Byte value) {
        if (registry.containsKey(value)) {
            return registry.get(value);
        }
        return new GnHeaderType(value, "Unknown");
    }

    public static GnHeaderType register(GnHeaderType type) {
        return registry.put(type.value(), type);
    }

    @Override
    public int compareTo(GnHeaderType o) {
        return value().compareTo(o.value());
    }

    @Override
    public String toString() {
        return name() + " (" + valueAsString() + ")";
    }
}
