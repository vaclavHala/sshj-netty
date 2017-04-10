package toy.exec.com.handler;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;

/**
 * We can only pass single object through netty pipe and
 * sshj needs packet and type separately because type can
 * be read from SSHPacket only once. Yeah...
 */
public class SSHPacketWrapper {

    public final SSHPacket packet;
    public final Message messageType;

    /**
     * Reads and caches message type from packet
     */
    public SSHPacketWrapper(SSHPacket packet) throws Buffer.BufferException {
        this.packet = packet;
        this.messageType = packet.readMessageID();
    }
}
