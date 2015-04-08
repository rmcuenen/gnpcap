package cuenen.raymond.gn.packet.namednumber;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.namednumber.NamedNumber;

public final class ItsStationType extends NamedNumber<Integer, ItsStationType> {

    public static final ItsStationType UNKNOWN = new ItsStationType(0, "Unknown");
    public static final ItsStationType PEDESTRIAN = new ItsStationType(1, "Pedestrian");
    public static final ItsStationType CYCLIST = new ItsStationType(2, "Cyclist");
    public static final ItsStationType MOPED = new ItsStationType(3, "Mooped");
    public static final ItsStationType MOTERCYCLE = new ItsStationType(4, "Motorcycle");
    public static final ItsStationType PASSENGER_CAR = new ItsStationType(5, "Passenger Car");
    public static final ItsStationType BUS = new ItsStationType(6, "Bus");
    public static final ItsStationType LIGHT_TRUCK = new ItsStationType(7, "Light Truck");
    public static final ItsStationType HEAVY_TRUCK = new ItsStationType(8, "Heavy Truck");
    public static final ItsStationType TRAILER = new ItsStationType(9, "Trailer");
    public static final ItsStationType SPECIAL_VEHICLE = new ItsStationType(10, "Special Vehicle");
    public static final ItsStationType TRAM = new ItsStationType(11, "Tram");
    public static final ItsStationType ROAD_SIDE_UNIT = new ItsStationType(15, "Road Side Unit");

    private static final Map<Integer, ItsStationType> registry = new HashMap<>();

    static {
        registry.put(UNKNOWN.value(), UNKNOWN);
        registry.put(PEDESTRIAN.value(), PEDESTRIAN);
        registry.put(CYCLIST.value(), CYCLIST);
        registry.put(MOPED.value(), MOPED);
        registry.put(MOTERCYCLE.value(), MOTERCYCLE);
        registry.put(PASSENGER_CAR.value(), PASSENGER_CAR);
        registry.put(BUS.value(), BUS);
        registry.put(LIGHT_TRUCK.value(), LIGHT_TRUCK);
        registry.put(HEAVY_TRUCK.value(), HEAVY_TRUCK);
        registry.put(TRAILER.value(), TRAILER);
        registry.put(SPECIAL_VEHICLE.value(), SPECIAL_VEHICLE);
        registry.put(TRAM.value(), TRAM);
        registry.put(ROAD_SIDE_UNIT.value(), ROAD_SIDE_UNIT);
    }

    public ItsStationType(Integer value, String name) {
        super(value, name);
    }

    public static ItsStationType getInstance(Integer value) {
        if (registry.containsKey(value)) {
            return registry.get(value);
        } else {
            return new ItsStationType(value, "Unknown");
        }
    }

    public static ItsStationType register(ItsStationType type) {
        return registry.put(type.value(), type);
    }

    @Override
    public int compareTo(ItsStationType o) {
        return value().compareTo(o.value());
    }

    @Override
    public String toString() {
        return name() + " (" + valueAsString() + ")";
    }
}
