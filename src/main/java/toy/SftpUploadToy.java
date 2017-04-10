package toy;

import toy.exec.com.OurConfig;
import toy.exec.com.handler.SshNettyTransport;
import toy.exec.com.initializer.SshInitializer;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Method;
import static java.nio.charset.StandardCharsets.US_ASCII;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.time.Instant;
import lombok.extern.slf4j.Slf4j;
import net.schmizz.keepalive.KeepAliveProvider;
import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.Service;
import net.schmizz.sshj.common.*;
import net.schmizz.sshj.connection.Connection;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.ConnectionImpl;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.connection.channel.direct.Session.Shell;
import net.schmizz.sshj.connection.channel.direct.SessionChannel;
import net.schmizz.sshj.sftp.SFTPClient;
import net.schmizz.sshj.sftp.SFTPEngine;
import net.schmizz.sshj.signature.Signature;
import net.schmizz.sshj.signature.SignatureECDSA;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.digest.Digest;
import net.schmizz.sshj.transport.digest.SHA256;
import net.schmizz.sshj.transport.kex.Curve25519DH;
import net.schmizz.sshj.transport.kex.Curve25519SHA256;
import net.schmizz.sshj.transport.random.Random;
import net.schmizz.sshj.transport.verification.HostKeyVerifier;
import net.schmizz.sshj.userauth.UserAuth;
import net.schmizz.sshj.userauth.UserAuthImpl;
import net.schmizz.sshj.userauth.method.AuthMethod;
import net.schmizz.sshj.userauth.method.AuthPassword;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.Resource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SftpUploadToy {

    static {
        System.setProperty("logback.configurationFile", "/s/data/mycroft/git/apComController/sftp/src/main/resources/logback-standalone.xml");
    }

    static Config config = new OurConfig();
    static Logger log;

    public static void main(String[] args) throws Throwable {

        log = LoggerFactory.getLogger(SftpUploadToy.class);
        log.info("\n\n--- START @ {} ---\n", Instant.now());

        //        our();
        sshj();

    }

    public static void sshj() throws Exception {
        final SSHClient ssh = new SSHClient(config);
        //        ssh.loadKnownHosts();
        ssh.addHostKeyVerifier("f8:17:fb:91:84:50:49:2a:e7:0a:00:e4:43:bf:e2:8c");
        ssh.connect("localhost");
        try {
            ssh.authPassword("hala", "secret");

            doShell(ssh.startSession());

            //            ssh.authPublickey(System.getProperty("user.name"));
            //            final String src = System.getProperty("user.home") + File.separator + "test_file";
            //            final SFTPClient sftp = ssh.newSFTPClient();
            //            try {
            //                sftp.put(new FileSystemFile(src), "/tmp");
            //            } finally {
            //                sftp.close();
            //            }
        } finally {
            ssh.disconnect();
        }
    }

    public static void our() throws Throwable {

        EventLoopGroup group = new NioEventLoopGroup();
        try {
            Bootstrap boot = new Bootstrap().channel(NioSocketChannel.class)
                                            .group(group)
                                            .handler(new ChannelInitializer<Channel>() {

                                                @Override
                                                protected void initChannel(Channel ch) throws Exception {
                                                    new SshInitializer().accept(ch);
                                                }
                                            });

            ChannelFuture chf = boot.connect("localhost", 22).awaitUninterruptibly();
            if (!chf.isSuccess()) {
                throw chf.cause();
            }
            Channel chan = chf.channel();
            log.info("channel connected");

            Transport transLayer = chan.pipeline().get(SshNettyTransport.class);

            UserAuth authLayer = new UserAuthImpl(transLayer);
            Connection connLayer = new ConnectionImpl(transLayer, KeepAliveProvider.HEARTBEAT);

            String username = "hala";
            AuthMethod method = new AuthPassword(new PasswordFinder() {

                @Override
                public char[] reqPassword(Resource<?> resource) {
                    return "secret".toCharArray();
                }

                @Override
                public boolean shouldRetry(Resource<?> resource) {
                    return false;
                }
            });
            authLayer.authenticate(username, (Service) connLayer, method, 1000 * 5);

            SessionChannel sess = new SessionChannel(connLayer);
            sess.open();

            doShell(sess);

            //            SFTPEngine engine = new SFTPEngine(() -> {
            //                //          checkConnected();
            //                //        checkAuthenticated();
            //                final SessionChannel sess = new SessionChannel(connLayer);
            //                sess.open();
            //                return sess;
            //            });
            //            SFTPClient sftp = new SFTPClient(engine);
        } finally {
            group.shutdownGracefully().awaitUninterruptibly();
        }
    }

    private static void doShell(Session sess) throws Exception {
        Shell sh = sess.startShell();
        InputStream in = sh.getInputStream();
        BufferedReader br = new BufferedReader(new InputStreamReader(in));
        OutputStream out = sh.getOutputStream();
        log.debug("WRITE");
        out.write("ls\n".getBytes(US_ASCII));
        out.flush();
        log.debug("READ");
        System.out.println(br.readLine());
    }
}
