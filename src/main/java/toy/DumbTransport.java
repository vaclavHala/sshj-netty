package toy;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.schmizz.sshj.AbstractService;
import net.schmizz.sshj.Config;
import net.schmizz.sshj.Service;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.DisconnectListener;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.verification.AlgorithmsVerifier;
import net.schmizz.sshj.transport.verification.HostKeyVerifier;

@Slf4j
public class DumbTransport implements Transport {

    private final Config config;
    private Service service;

    public DumbTransport(Config config) {
        this.config = config;
        this.service = new NullService(this);
    }

    @Override
    public void init(String host, int port, InputStream in, OutputStream out) throws TransportException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void addHostKeyVerifier(HostKeyVerifier hkv) {
        log.info("addHostKeyVerifier hkv {}", hkv);
    }

    @Override
    public void addAlgorithmsVerifier(AlgorithmsVerifier verifier) {
        log.info("addAlgorithmsVerifier verifier{}", verifier);

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
        return 0;
    }

    @Override
    public void setTimeoutMs(int timeout) {
        log.info("setTimeoutMs timeout {}", timeout);

    }

    @Override
    public int getHeartbeatInterval() {
        log.info("getHeartbeatInterval");
        return 0;
    }

    @Override
    public void setHeartbeatInterval(int interval) {
        log.info("setHeartbeatInterval interval {}", interval);

    }

    @Override
    public String getRemoteHost() {
        log.info("getRemoteHost");

        return null;
    }

    @Override
    public int getRemotePort() {
        log.info("getRemotePort");

        return 0;
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
        log.info("reqService service {}", service);

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
    public void join() throws TransportException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void join(int timeout, TimeUnit unit) throws TransportException {
        throw new UnsupportedOperationException();

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
    public long write(SSHPacket payload) throws TransportException {
        log.info("write payload {}", payload);

        return 0;
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
    public void die(Exception e) {
        log.info("die e {}", e);

    }

    @Override
    public void handle(Message msg, SSHPacket buf) throws SSHException {
        log.info("handle msg {}, buf {}", msg, buf);

    }

    private static final class NullService extends AbstractService {

        NullService(Transport trans) {
            super("null-service", trans);
        }

    }

}
