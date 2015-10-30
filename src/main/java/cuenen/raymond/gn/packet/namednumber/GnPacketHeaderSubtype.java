package cuenen.raymond.gn.packet.namednumber;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.namednumber.NamedNumber;

public final class GnPacketHeaderSubtype extends NamedNumber<Byte, GnPacketHeaderSubtype> {

    public static final GnPacketHeaderSubtype UNSPECIFIED = new GnPacketHeaderSubtype((byte) 0, "Unspecified");
    public static final GnPacketHeaderSubtype CIRCLE = new GnPacketHeaderSubtype((byte) 0, "Circle");
    public static final GnPacketHeaderSubtype RECTANGLE = new GnPacketHeaderSubtype((byte) 1, "Rectangle");
    public static final GnPacketHeaderSubtype ELLIPSE = new GnPacketHeaderSubtype((byte) 2, "Ellipse");
    public static final GnPacketHeaderSubtype SINGLE_HOP = new GnPacketHeaderSubtype((byte) 0, "Single Hop");
    public static final GnPacketHeaderSubtype MULTI_HOP = new GnPacketHeaderSubtype((byte) 1, "Multi Hop");
    public static final GnPacketHeaderSubtype REQUEST = new GnPacketHeaderSubtype((byte) 0, "Request");
    public static final GnPacketHeaderSubtype REPLY = new GnPacketHeaderSubtype((byte) 1, "Reply");

    private static final Map<GnPacketHeaderType, Map<Byte, GnPacketHeaderSubtype>> registry = new HashMap<>();

    static {
        registry.put(GnPacketHeaderType.ANY, new HashMap<Byte, GnPacketHeaderSubtype>() {
            {
                put(UNSPECIFIED.value(), UNSPECIFIED);
            }
        });
        registry.put(GnPacketHeaderType.BEACON, new HashMap<Byte, GnPacketHeaderSubtype>() {
            {
                put(UNSPECIFIED.value(), UNSPECIFIED);
            }
        });
        registry.put(GnPacketHeaderType.GEOUNICAST, new HashMap<Byte, GnPacketHeaderSubtype>() {
            {
                put(UNSPECIFIED.value(), UNSPECIFIED);
            }
        });
        registry.put(GnPacketHeaderType.GEOANYCAST, new HashMap<Byte, GnPacketHeaderSubtype>() {
            {
                put(CIRCLE.value(), CIRCLE);
                put(RECTANGLE.value(), RECTANGLE);
                put(ELLIPSE.value(), ELLIPSE);
            }
        });
        registry.put(GnPacketHeaderType.GEOBROADCAST, new HashMap<Byte, GnPacketHeaderSubtype>() {
            {
                put(CIRCLE.value(), CIRCLE);
                put(RECTANGLE.value(), RECTANGLE);
                put(ELLIPSE.value(), ELLIPSE);
            }
        });
        registry.put(GnPacketHeaderType.TSB, new HashMap<Byte, GnPacketHeaderSubtype>() {
            {
                put(SINGLE_HOP.value(), SINGLE_HOP);
                put(MULTI_HOP.value(), MULTI_HOP);
            }
        });
        registry.put(GnPacketHeaderType.LS, new HashMap<Byte, GnPacketHeaderSubtype>() {
            {
                put(REQUEST.value(), REQUEST);
                put(REPLY.value(), REPLY);
            }
        });
    }

    public GnPacketHeaderSubtype(Byte value, String name) {
        super(value, name);
    }

    public static GnPacketHeaderSubtype getInstance(GnPacketHeaderType type, Byte value) {
        if (registry.containsKey(type)) {
            return getInstance(registry.get(type), value);
        }
        return new GnPacketHeaderSubtype(value, "Unknown");
    }

    private static GnPacketHeaderSubtype getInstance(Map<Byte, GnPacketHeaderSubtype> map, Byte value) {
        if (map.containsKey(value)) {
            return map.get(value);
        }
        return new GnPacketHeaderSubtype(value, "Unknown");
    }

    public static GnPacketHeaderSubtype register(GnPacketHeaderType type, GnPacketHeaderSubtype subtype) {
        Map<Byte, GnPacketHeaderSubtype> map = registry.get(type);
        if (map == null) {
            map = new HashMap<>();
            registry.put(type, map);
        }
        return map.put(subtype.value(), subtype);
    }

    @Override
    public int compareTo(GnPacketHeaderSubtype o) {
        return value().compareTo(o.value());
    }

    @Override
    public String toString() {
        return name() + " (" + valueAsString() + ")";
    }
}
