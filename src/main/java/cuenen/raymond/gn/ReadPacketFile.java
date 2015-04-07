package cuenen.raymond.gn;

import java.sql.Timestamp;
import java.util.concurrent.atomic.AtomicInteger;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

public class ReadPacketFile {

    public static void main(String[] args) throws Exception {
        final PcapHandle handle = Pcaps.openOffline("rx.pcap");
        final AtomicInteger count = new AtomicInteger(0);
        final PacketListener listener = new PacketListener() {

            @Override
            public void gotPacket(Packet packet) {
                Timestamp ts = new Timestamp(handle.getTimestampInts() * 1000L);
                ts.setNanos(handle.getTimestampMicros() * 1000);
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
