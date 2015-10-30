package cuenen.raymond.gn;

import java.util.concurrent.atomic.AtomicInteger;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

public class ReadPacketFile {

    public static void main(String[] args) throws Exception {
        final PcapHandle handle = Pcaps.openOffline("tx.pcap");
        final AtomicInteger count = new AtomicInteger(0);
        final PacketListener listener = new PacketListener() {

            @Override
            public void gotPacket(Packet packet) {
                System.out.println(handle.getTimestamp());
                System.out.println(count.incrementAndGet());
                System.out.println(packet);
            }
        };
        try {
            handle.loop(-1, listener);
        } finally {
            handle.close();
        }
    }
}
