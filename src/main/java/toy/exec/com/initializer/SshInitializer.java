package toy.exec.com.initializer;

import toy.exec.com.OurConfig;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.handler.logging.LoggingHandler;
import java.security.PublicKey;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import net.schmizz.sshj.Config;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.transport.verification.HostKeyVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import toy.exec.com.handler.*;

@Slf4j
public class SshInitializer implements Consumer<Channel> {

    private static final Logger LOG_LIFE = LoggerFactory.getLogger(SshInitializer.class.getSimpleName() + "_LIFE");
    private static final Logger LOG_RAW = LoggerFactory.getLogger(SshInitializer.class.getSimpleName() + "_RAW");

    //
    //    private final Provider<Integer> connectionTimeout;
    //
    //    @Inject
    //    public SftpInitializer(
    //            @CCProperty(CONNECTION_TIMEOUT) final Provider<Integer> connectionTimeout,
    //            final Provider<LzqjDataParser> parserFactory) {
    //        this.connectionTimeout = connectionTimeout;
    //        this.parserFactory = parserFactory;
    //    }
    //
    @Override
    public void accept(final Channel channel) {
        //        SocketChannel channel = (SocketChannel) c;
        //        final SocketChannelConfig config = channel.config();
        //        int timeout = this.connectionTimeout.get();
        //        log.debug("Setting connection timeout to : {} ms.", timeout);
        //        config.setConnectTimeoutMillis(timeout);
        //        config.setTcpNoDelay(true);
        //
        channel.pipeline().addLast(this.handlers());
    }

    public ChannelHandler[] handlers() {
        Config cfg = new OurConfig();
        return new ChannelHandler[]{new LoggingHandler(),
                                    //            new MarkedLifecycleLoggingHandler(this.LOG_LIFE),
                                    //                                    new BoundaryHexDumpLoggingHandler(this.LOG_RAW),

                                    new SshIdentDecoder(),
                                    new SshIdentHandler(),

                                    new SshPacketDecoder(),
                                    //                                    new BoundaryHexDumpLoggingHandler(LoggerFactory.getLogger("PACKET")),
                                    new SshPacketCodec(cfg.getRandomFactory().create()),
                                    new SshKexCodec(cfg, asList(
                                                    new HostKeyVerifier() {

                                                        @Override
                                                        public boolean verify(String h, int p, PublicKey k) {
                                                            return SecurityUtils.getFingerprint(k).equals("f8:17:fb:91:84:50:49:2a:e7:0a:00:e4:43:bf:e2:8c");
                                                        }
                                                    }
                                                    ), emptyList()),
                                    new SshNettyTransport(cfg)
        };
    }
}
