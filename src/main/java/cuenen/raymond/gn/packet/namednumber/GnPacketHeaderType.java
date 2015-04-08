package cuenen.raymond.gn.packet.namednumber;

import static cuenen.raymond.gn.packet.namednumber.GnPacketHeaderType.HeaderSubtype.*;
import cuenen.raymond.gn.util.BitValues;
import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.namednumber.NamedNumber;

public final class GnPacketHeaderType extends NamedNumber<Byte, GnPacketHeaderType> {

    public static final GnPacketHeaderType ANY = new GnPacketHeaderType((byte) 0, "Unspecified", UNSPECIFIED);
    public static final GnPacketHeaderType BEACON = new GnPacketHeaderType((byte) 16, "Beacon", UNSPECIFIED);
    public static final GnPacketHeaderType GEOUNICAST = new GnPacketHeaderType((byte) 32, "GeoUnicast", UNSPECIFIED);
    public static final GnPacketHeaderType GEOANYCAST_CIRCLE = new GnPacketHeaderType((byte) 48, "GeoAnycast", CIRCLE);
    public static final GnPacketHeaderType GEOANYCAST_RECT = new GnPacketHeaderType((byte) 49, "GeoAnycast", RECTANGLE);
    public static final GnPacketHeaderType GEOANYCAST_ELIP = new GnPacketHeaderType((byte) 50, "GeoAnycast", ELLIPSE);
    public static final GnPacketHeaderType GEOBROADCAST_CIRCLE = new GnPacketHeaderType((byte) 64, "GeoBroadcast", CIRCLE);
    public static final GnPacketHeaderType GEOBROADCAST_RECT = new GnPacketHeaderType((byte) 65, "GeoBroadcast", RECTANGLE);
    public static final GnPacketHeaderType GEOBROADCAST_ELIP = new GnPacketHeaderType((byte) 66, "GeoBroadcast", ELLIPSE);
    public static final GnPacketHeaderType TSB_SINGLE = new GnPacketHeaderType((byte) 80, "TSB", SINGLE_HOP);
    public static final GnPacketHeaderType TSB_MULTI = new GnPacketHeaderType((byte) 81, "TSB", MULTI_HOP);
    public static final GnPacketHeaderType LS_REQUEST = new GnPacketHeaderType((byte) 6, "LS", REQUEST);
    public static final GnPacketHeaderType LS_REPLY = new GnPacketHeaderType((byte) 6, "LS", REPLY);

    private static final Map<Byte, GnPacketHeaderType> registry = new HashMap<>();

    static {
        registry.put(ANY.value(), ANY);
        registry.put(BEACON.value(), BEACON);
        registry.put(GEOUNICAST.value(), GEOUNICAST);
        registry.put(GEOANYCAST_CIRCLE.value(), GEOANYCAST_CIRCLE);
        registry.put(GEOANYCAST_RECT.value(), GEOANYCAST_RECT);
        registry.put(GEOANYCAST_ELIP.value(), GEOANYCAST_ELIP);
        registry.put(GEOBROADCAST_CIRCLE.value(), GEOBROADCAST_CIRCLE);
        registry.put(GEOBROADCAST_RECT.value(), GEOBROADCAST_RECT);
        registry.put(GEOBROADCAST_ELIP.value(), GEOBROADCAST_ELIP);
        registry.put(TSB_SINGLE.value(), TSB_SINGLE);
        registry.put(TSB_MULTI.value(), TSB_MULTI);
        registry.put(LS_REQUEST.value(), LS_REQUEST);
        registry.put(LS_REPLY.value(), LS_REPLY);
    }

    private final HeaderSubtype subtype;

    public GnPacketHeaderType(Byte value, String name, HeaderSubtype subtype) {
        super(value, name);
        this.subtype = subtype;
    }

    public HeaderSubtype getSubtype() {
        return subtype;
    }

    public static GnPacketHeaderType getInstance(Byte value) {
        if (registry.containsKey(value)) {
            return registry.get(value);
        } else {
            return new GnPacketHeaderType(value, "Unspecified", UNSPECIFIED);
        }
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
        return name() + " (" + BitValues.getValue(value(), 0, 4) + ")";
    }

    public static enum HeaderSubtype {

        UNSPECIFIED((byte) 0, "Unspecified"),
        CIRCLE((byte) 0, "Circle"),
        RECTANGLE((byte) 1, "Rectangle"),
        ELLIPSE((byte) 2, "Ellipse"),
        SINGLE_HOP((byte) 0, "Single Hop"),
        MULTI_HOP((byte) 1, "Multi Hop"),
        REQUEST((byte) 0, "Request"),
        REPLY((byte) 1, "Reply");

        private final byte value;
        private final String name;

        private HeaderSubtype(byte value, String name) {
            this.value = value;
            this.name = name;
        }

        @Override
        public String toString() {
            return name + " (" + value + ")";
        }
    }
}
