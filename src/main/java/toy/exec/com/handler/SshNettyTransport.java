package toy.exec.com.handler;

import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import io.netty.channel.ChannelHandlerContext;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import net.schmizz.sshj.AbstractService;
import net.schmizz.sshj.Config;
import net.schmizz.sshj.Service;
import net.schmizz.sshj.common.*;
import net.schmizz.sshj.transport.*;
import net.schmizz.sshj.transport.verification.AlgorithmsVerifier;
import net.schmizz.sshj.transport.verification.HostKeyVerifier;

@Slf4j
public class SshNettyTransport extends ChannelDuplexHandler implements Transport {

    private final Config config;
    private Service service;

    private Channel chan;

    public SshNettyTransport(Config config) {
        this.config = config;
        this.service = new NullService(this);
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        log.debug("Transport active: {}", ctx.channel());
        this.chan = ctx.channel();
        ctx.fireChannelActive();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.debug("Transport inactive: {}", ctx.channel());
        this.chan = null;
        ctx.fireChannelInactive();
    }

    @Override
    public long write(SSHPacket payload) throws TransportException {
        if (this.chan == null) {
            throw new TransportException("Channel is not active");
        }

        log.debug("write payload {} to {}", payload, this.chan);
        this.chan.writeAndFlush(payload).addListener(FIRE_EXCEPTION_ON_FAILURE);

        return 1;
    }

    @Override
    public void handle(Message msg, SSHPacket buf) throws SSHException {
        log.info("handle msg {}, buf {}", msg, buf);

        if (msg.geq(50)) {
            // not a transport layer packet
            this.service.handle(msg, buf);
        } else if (msg.in(20, 21) || msg.in(30, 49)) {
            // kex packet
            // TODO kexer.handle(msg, buf);
        } else {
            switch (msg) {
                case DISCONNECT : {
                    this.gotDisconnect(buf);
                    break;
                }
                case IGNORE : {
                    log.debug("Received SSH_MSG_IGNORE");
                    break;
                }
                case UNIMPLEMENTED : {
                    this.gotUnimplemented(buf);
                    break;
                }
                case DEBUG : {
                    this.gotDebug(buf);
                    break;
                }
                case SERVICE_ACCEPT : {
                    this.gotServiceAccept();
                    break;
                }
                case USERAUTH_BANNER : {
                    log.debug("Received USERAUTH_BANNER");
                    break;
                }
                default :
                    sendUnimplemented();
            }
        }
    }

    private void gotDebug(SSHPacket buf) throws TransportException {
        try {
            final boolean display = buf.readBoolean();
            final String message = buf.readString();
            log.debug("Received SSH_MSG_DEBUG (display={}) '{}'", display, message);
        } catch (Buffer.BufferException be) {
            throw new TransportException(be);
        }
    }

    private void gotDisconnect(SSHPacket buf) throws TransportException {
        try {
            final DisconnectReason code = DisconnectReason.fromInt(buf.readUInt32AsInt());
            final String message = buf.readString();
            log.info("Received SSH_MSG_DISCONNECT (reason={}, msg={})", code, message);
            throw new TransportException(code, message);
        } catch (Buffer.BufferException be) {
            throw new TransportException(be);
        }
    }

    private void gotServiceAccept() throws TransportException {
        //        serviceAccept.lock();
        //        try {
        //            if (!serviceAccept.hasWaiters())
        //                throw new TransportException(DisconnectReason.PROTOCOL_ERROR,
        //                                             "Got a service accept notification when none was awaited");
        //            serviceAccept.set();
        //        } finally {
        //            serviceAccept.unlock();
        //        }
    }

    private void gotUnimplemented(SSHPacket packet) throws SSHException {
        long seqNum = packet.readUInt32();
        log.debug("Received SSH_MSG_UNIMPLEMENTED #{}", seqNum);
        //        if (kexer.isKexOngoing()) {
        //            throw new TransportException("Received SSH_MSG_UNIMPLEMENTED while exchanging keys");
        //    }
        this.service.notifyUnimplemented(seqNum);
    }

    @Override
    public void doKex() throws TransportException {
        log.info("doKex");
    }

    @Override
    public String getClientVersion() {
        log.info("getClientVersion");
        return null;
    }

    @Override
    public Config getConfig() {
        log.info("getConfig");
        return this.config;
    }

    @Override
    public int getTimeoutMs() {
        log.info("getTimeoutMs");
        return 100000;
    }

    @Override
    public void setTimeoutMs(int timeout) {
        log.info("setTimeoutMs timeout {}", timeout);

    }

    @Override
    public int getHeartbeatInterval() {
        log.info("getHeartbeatInterval");
        return 5000;
    }

    @Override
    public void setHeartbeatInterval(int interval) {
        log.info("setHeartbeatInterval interval {}", interval);

    }

    @Override
    public String getRemoteHost() {
        log.info("getRemoteHost");

        InetSocketAddress addr = (InetSocketAddress) this.chan.remoteAddress();
        return addr.getHostString();
    }

    @Override
    public int getRemotePort() {
        log.info("getRemotePort");

        InetSocketAddress addr = (InetSocketAddress) this.chan.remoteAddress();
        return addr.getPort();
    }

    @Override
    public String getServerVersion() {
        log.info("getServerVersion");

        return null;
    }

    @Override
    public byte[] getSessionID() {
        log.info("getSessionID");

        return null;
    }

    @Override
    public Service getService() {
        log.info("getService");

        return this.service;
    }

    @Override
    public void reqService(Service service) throws TransportException {
        log.info("reqService service {}", service.getName());

        log.debug("Sending SSH_MSG_SERVICE_REQUEST for {}", service.getName());
        this.write(new SSHPacket(Message.SERVICE_REQUEST).putString(service.getName()));
    }

    @Override
    public void setService(Service service) {
        log.info("setService service {}", service);

        if (service == null) {
            this.service = new NullService(this);
        } else {
            this.service = service;
        }
    }

    @Override
    public boolean isAuthenticated() {
        log.info("isAuthenticated");

        return false;
    }

    @Override
    public void setAuthenticated() {
        log.info("setAuthenticated");

    }

    @Override
    public long sendUnimplemented() throws TransportException {
        log.info("sendUnimplemented");

        return 0;
    }

    @Override
    public boolean isRunning() {
        log.info("isRunning");

        return false;
    }

    @Override
    public void disconnect() {
        log.info("disconnect");

    }

    @Override
    public void disconnect(DisconnectReason reason) {
        log.info("disconnect reason {}", reason);

    }

    @Override
    public void disconnect(DisconnectReason reason, String message) {
        log.info("disconnect reason {} message {}", reason, message);

    }

    @Override
    public void die(Exception e) {
        log.info("die e {}", e);

    }

    private static final class NullService extends AbstractService {

        NullService(Transport trans) {
            super("null-service", trans);
        }

    }

    //<editor-fold defaultstate="collapsed" desc="SSHJ - Unused">
    @Override
    public void init(String host, int port, InputStream in, OutputStream out) throws TransportException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void join() throws TransportException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void join(int timeout, TimeUnit unit) throws TransportException {
        throw new UnsupportedOperationException();

    }

    @Override
    public void setDisconnectListener(DisconnectListener listener) {
        throw new UnsupportedOperationException();
    }

    @Override
    public DisconnectListener getDisconnectListener() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void addHostKeyVerifier(HostKeyVerifier hkv) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void addAlgorithmsVerifier(AlgorithmsVerifier verifier) {
        throw new UnsupportedOperationException();

    }

    //</editor-fold>

}
