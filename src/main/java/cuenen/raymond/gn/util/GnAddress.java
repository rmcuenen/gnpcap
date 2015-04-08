package cuenen.raymond.gn.util;

import cuenen.raymond.gn.packet.namednumber.ItsStationType;
import java.util.regex.Matcher;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.LinkLayerAddress;

public final class GnAddress extends LinkLayerAddress {

    public static final int SIZE_IN_BYTES = 8;

    private GnAddress(byte[] address) {
        super(address);
    }

    public static GnAddress getByAddress(byte[] address) {
        if (address.length != SIZE_IN_BYTES) {
            throw new IllegalArgumentException();
        }
        return new GnAddress(ByteArrays.clone(address));
    }

    public static GnAddress getByName(String name) {
        Matcher m = HEX_SEPARATOR_PATTERN.matcher(name);
        m.find();
        return getByName(name, m.group(1));
    }

    public static GnAddress getByName(String name, String separator) {
        return getByAddress(ByteArrays.parseByteArray(name, separator));
    }

    public boolean isManuallyConfigured() {
        return (getAddress()[0] & 0x80) != 0;
    }

    public ItsStationType getStationType() {
        return ItsStationType.getInstance(getAddress()[0] & 0x7C);
    }

    public int getCountryCode() {
        int cc = (getAddress()[0] & 0x03) << 8;
        return cc | getAddress()[1];
    }

    public LinkLayerAddress getLinkLayerAddress() {
        return LinkLayerAddress.getByAddress(ByteArrays.getSubArray(getAddress(), 2));
    }
}
