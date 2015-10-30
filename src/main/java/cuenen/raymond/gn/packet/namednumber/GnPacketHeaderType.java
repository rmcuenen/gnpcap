package cuenen.raymond.gn.packet.namednumber;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.namednumber.NamedNumber;

public final class GnPacketHeaderType extends NamedNumber<Byte, GnPacketHeaderType> {

    public static final GnPacketHeaderType ANY = new GnPacketHeaderType((byte) 0, "Any");
    public static final GnPacketHeaderType BEACON = new GnPacketHeaderType((byte) 1, "Beacon");
    public static final GnPacketHeaderType GEOUNICAST = new GnPacketHeaderType((byte) 2, "GeoUnicast");
    public static final GnPacketHeaderType GEOANYCAST = new GnPacketHeaderType((byte) 3, "GeoAnycast");
    public static final GnPacketHeaderType GEOBROADCAST = new GnPacketHeaderType((byte) 4, "GeoBroadcast");
    public static final GnPacketHeaderType TSB = new GnPacketHeaderType((byte) 5, "TSB");
    public static final GnPacketHeaderType LS = new GnPacketHeaderType((byte) 6, "LS");

    private static final Map<Byte, GnPacketHeaderType> registry = new HashMap<>();

    static {
        registry.put(ANY.value(), ANY);
        registry.put(BEACON.value(), BEACON);
        registry.put(GEOUNICAST.value(), GEOUNICAST);
        registry.put(GEOANYCAST.value(), GEOANYCAST);
        registry.put(GEOBROADCAST.value(), GEOBROADCAST);
        registry.put(TSB.value(), TSB);
        registry.put(LS.value(), LS);
    }

    public GnPacketHeaderType(Byte value, String name) {
        super(value, name);
    }

    public static GnPacketHeaderType getInstance(Byte value) {
        if (registry.containsKey(value)) {
            return registry.get(value);
        }
        return new GnPacketHeaderType(value, "Unspecified");
    }

    public static GnPacketHeaderType register(GnPacketHeaderType type) {
        return registry.put(type.value(), type);
    }

    @Override
    public int compareTo(GnPacketHeaderType o) {
        return value().compareTo(o.value());
    }

    @Override
    public String toString() {
        return name() + " (" + valueAsString() + ")";
    }
}
