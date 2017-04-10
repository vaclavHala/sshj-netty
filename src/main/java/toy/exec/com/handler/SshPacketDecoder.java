package toy.exec.com.handler;

import io.netty.handler.codec.*;
import lombok.extern.slf4j.Slf4j;

/**
 *     uint32    packet_length
 *     byte      padding_length
 *     byte[n1]  payload; n1 = packet_length - padding_length - 1
 *     byte[n2]  random padding; n2 = padding_length
 *     byte[m]   mac (Message Authentication Code - MAC); m = mac_length
 */
@Slf4j
public class SshPacketDecoder extends LengthFieldBasedFrameDecoder {

    private static final int MAX_PACKET_LEN = 256 * 1024;

    // FIXME mac ?

    public SshPacketDecoder() {
        // -1 we want to handle length calculation ourselves
        super(MAX_PACKET_LEN, 0, 4, 0, 0, true);

    }
}
