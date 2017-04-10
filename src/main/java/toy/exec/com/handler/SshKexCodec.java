package toy.exec.com.handler;

import toy.exec.com.handler.SshIdentHandler.SshIdentInfo;
import io.netty.buffer.ByteBuf;
import static io.netty.buffer.ByteBufUtil.hexDump;
import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.*;
import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.extern.slf4j.Slf4j;
import net.schmizz.concurrent.Event;
import net.schmizz.sshj.Config;
import net.schmizz.sshj.common.*;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.TransportImpl;
import net.schmizz.sshj.transport.cipher.Cipher;
import net.schmizz.sshj.transport.compression.Compression;
import net.schmizz.sshj.transport.digest.Digest;
import net.schmizz.sshj.transport.kex.KeyExchange;
import net.schmizz.sshj.transport.mac.MAC;
import net.schmizz.sshj.transport.verification.AlgorithmsVerifier;
import net.schmizz.sshj.transport.verification.HostKeyVerifier;
import org.slf4j.Logger;

/**
 * When key exchange is in progress buffers all outbound messages,
 * unleashes these in batch once key is exchanged.
 */
@Slf4j
public class SshKexCodec extends ChannelDuplexHandler {

    private static final int MSG_TYPE_INDEX = 5;

    /**
     * {@link HostKeyVerifier#verify(String, int, java.security.PublicKey)} is invoked by {@link #verifyHost(PublicKey)}
     * when we are ready to verify the the server's host key.
     */
    private final Queue<HostKeyVerifier> hostVerifiers = new LinkedList<>();

    private final Queue<AlgorithmsVerifier> algorithmVerifiers = new LinkedList<>();

    private final AtomicBoolean kexOngoing = new AtomicBoolean();

    /** What we are expecting from the next packet */
    private Expected expected = Expected.KEXINIT;

    /** Instance of negotiated key exchange algorithm */
    private KeyExchange kex;

    /** Computed session ID */
    private byte[] sessionID;

    // received from InitPhase handler
    private String serverId;
    private String clientId;

    // TODO pass this in event so we can update at runtime ?
    private final Config config;
    private Proposal clientProposal;
    private NegotiatedAlgorithms negotiatedAlgs;

    private Channel chan;

    private final Queue<Entry<Object, ChannelPromise>> tempBuffer;

    public SshKexCodec(
            Config config,
            Collection<HostKeyVerifier> hostKeyVerifiers,
            Collection<AlgorithmsVerifier> algoVerifiers) {
        this.config = config;
        this.tempBuffer = new LinkedList<>();
        this.hostVerifiers.addAll(hostKeyVerifiers);
        this.algorithmVerifiers.addAll(algoVerifiers);
    }

    /**
     * Returns the session identifier computed during key exchange.
     *
     * @return session identifier as a byte array
     */
    //    byte[] getSessionID() {
    //        return Arrays.copyOf(sessionID, sessionID.length);
    //    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof SshIdentInfo) {
            SshIdentInfo identInfo = (SshIdentInfo) msg;
            this.clientId = identInfo.clientId;
            this.serverId = identInfo.serverId;
            log.debug("Got idents, starting kex");
            startKex();
            return;
        }

        SSHPacketWrapper packet = (SSHPacketWrapper) msg;

        if (isKexMessage(packet.messageType)) {
            // kex packet
            this.handle(packet.messageType, packet.packet);
        } else {
            ctx.fireChannelRead(msg);
        }
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        if (this.kexOngoing.get() || this.negotiatedAlgs == null) {
            SSHPacket buf = (SSHPacket) msg;
            Message type = Message.fromByte(buf.array()[MSG_TYPE_INDEX]);
            log.error("MSG: {} {} {}", type, type.toByte(), hexDump(buf.array()));

            if (isKexMessage(type)) {
                log.debug("Letting kex msg through: {}", msg);
                ctx.write(msg, promise);
            } else {
                log.debug("Kexing now, buffering msg: {}", msg);
                this.tempBuffer.add(new SimpleEntry<>(msg, promise));
            }
        } else {
            log.debug("Not kexing now, passthrough: {}", msg);
            ctx.write(msg, promise);
        }
    }

    private boolean isKexMessage(Message type) {
        return type.in(20, 21) || type.in(30, 49);
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        log.debug("KEX active: {}", ctx.channel());
        this.chan = ctx.channel();
        ctx.fireChannelActive();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.debug("KEX inactive: {}", ctx.channel());
        this.chan = null;
        ctx.fireChannelInactive();
    }

    public void handle(Message msg, SSHPacket buf) throws TransportException {
        switch (expected) {

            case KEXINIT :
                ensureReceivedMatchesExpected(msg, Message.KEXINIT);
                log.debug("Received SSH_MSG_KEXINIT");
                startKex();
                /*
                * We block on this event to prevent a race condition where we may have received a SSH_MSG_KEXINIT before
                * having sent the packet ourselves (would cause gotKexInit() to fail)
                */
                //                kexInitSent.await(transport.getTimeoutMs(), TimeUnit.MILLISECONDS);
                gotKexInit(buf);
                expected = Expected.FOLLOWUP;
                break;

            case FOLLOWUP :
                ensureKexOngoing();
                log.debug("Received kex followup data");
                try {
                    if (kex.next(msg, buf)) {
                        verifyHost(kex.getHostKey());
                        log.debug("Sending SSH_MSG_NEWKEYS");
                        this.chan.writeAndFlush(new SSHPacket(Message.NEWKEYS));
                        expected = Expected.NEWKEYS;
                    }
                } catch (GeneralSecurityException e) {
                    throw new TransportException(DisconnectReason.KEY_EXCHANGE_FAILED, e);
                }
                break;

            case NEWKEYS :
                ensureReceivedMatchesExpected(msg, Message.NEWKEYS);
                ensureKexOngoing();
                log.debug("Received SSH_MSG_NEWKEYS");
                gotNewKeys();
                kexOngoing.set(false);

                for (Entry<Object, ChannelPromise> postponed : this.tempBuffer) {
                    this.chan.write(postponed.getKey(), postponed.getValue());
                }
                this.chan.flush();
                this.tempBuffer.clear();

                expected = Expected.KEXINIT;
                break;

            default :
                throw new IllegalStateException(expected.toString());

        }
    }

    /**
     * Starts key exchange by sending a {@code SSH_MSG_KEXINIT} packet. Key exchange needs to be done once mandatorily
     * after initializing the {@link Transport} for it to be usable and may be initiated at any later point e.g. if
     * {@link Transport#getConfig() algorithms} have changed and should be renegotiated.
     *
     * @throws TransportException if there is an error during key exchange
     * @see {@link Transport#setTimeoutMs} for setting timeout for kex
     */
    private void startKex() throws TransportException {
        if (!kexOngoing.getAndSet(true)) {
            log.debug("Sending SSH_MSG_KEXINIT");
            clientProposal = new Proposal(this.config);
            this.chan.writeAndFlush(clientProposal.getPacket());
        }
    }

    private void gotKexInit(SSHPacket buf) throws TransportException {
        buf.rpos(buf.rpos() - 1);
        final Proposal serverProposal = new Proposal(buf);
        negotiatedAlgs = clientProposal.negotiate(serverProposal);
        log.debug("Negotiated algorithms: {}", negotiatedAlgs);
        // FIXME if we need this do some wrapping gymnastics with our NegotiatedAlgos
        //        for (AlgorithmsVerifier v : algorithmVerifiers) {
        //            log.debug("Trying to verify algorithms with {}", v);
        //            if (!v.verify(negotiatedAlgs)) {
        //                throw new TransportException(DisconnectReason.KEY_EXCHANGE_FAILED,
        //                                             "Failed to verify negotiated algorithms `" + negotiatedAlgs + "`");
        //            }
        //        }
        kex = Factory.Named.Util.create(this.config.getKeyExchangeFactories(),
                                        negotiatedAlgs.getKeyExchangeAlgorithm());
        Transport trans = this.chan.pipeline().get(SshNettyTransport.class);
        try {
            kex.init(trans,
                     this.serverId, this.clientId,
                     serverProposal.getPacket().getCompactData(), clientProposal.getPacket().getCompactData());
        } catch (GeneralSecurityException e) {
            throw new TransportException(DisconnectReason.KEY_EXCHANGE_FAILED, e);
        }
    }

    /**
     * Tries to validate host key with all the host key verifiers known to this instance ( {@link #hostVerifiers})
     *
     * @param key the host key to verify
     *
     * @throws TransportException
     */
    private void verifyHost(PublicKey key) throws TransportException {
        InetSocketAddress addr = (InetSocketAddress) this.chan.remoteAddress();
        String host = addr.getHostString();
        int port = addr.getPort();
        for (HostKeyVerifier hkv : hostVerifiers) {
            log.debug("Trying to verify host key with {}", hkv);
            if (hkv.verify(host, port, key))
                return;
        }

        throw new TransportException(DisconnectReason.HOST_KEY_NOT_VERIFIABLE,
                                     "Could not verify `" + KeyType.fromKey(key) +
                                             "` host key with fingerprint `" + SecurityUtils.getFingerprint(key) +
                                             "` for `" + host +
                                             "` on port " + port);
    }

    /* See Sec. 7.2. "Output from Key Exchange", RFC 4253 */
    private void gotNewKeys() {
        final Digest hash = kex.getHash();

        final byte[] H = kex.getH();

        if (sessionID == null)
            // session id is 'H' from the first key exchange and does not change thereafter
            sessionID = H;

        final Buffer.PlainBuffer hashInput = new Buffer.PlainBuffer()
                                                                     .putMPInt(kex.getK())
                                                                     .putRawBytes(H)
                                                                     .putByte((byte) 0) // <placeholder>
                                                                     .putRawBytes(sessionID);
        final int pos = hashInput.available() - sessionID.length - 1; // Position of <placeholder>

        hashInput.array()[pos] = 'A';
        hash.update(hashInput.array(), 0, hashInput.available());
        final byte[] initialIV_C2S = hash.digest();

        hashInput.array()[pos] = 'B';
        hash.update(hashInput.array(), 0, hashInput.available());
        final byte[] initialIV_S2C = hash.digest();

        hashInput.array()[pos] = 'C';
        hash.update(hashInput.array(), 0, hashInput.available());
        final byte[] encryptionKey_C2S = hash.digest();

        hashInput.array()[pos] = 'D';
        hash.update(hashInput.array(), 0, hashInput.available());
        final byte[] encryptionKey_S2C = hash.digest();

        hashInput.array()[pos] = 'E';
        hash.update(hashInput.array(), 0, hashInput.available());
        final byte[] integrityKey_C2S = hash.digest();

        hashInput.array()[pos] = 'F';
        hash.update(hashInput.array(), 0, hashInput.available());
        final byte[] integrityKey_S2C = hash.digest();

        final Cipher cipher_C2S = Factory.Named.Util.create(this.config.getCipherFactories(),
                                                            negotiatedAlgs.getClient2ServerCipherAlgorithm());
        cipher_C2S.init(Cipher.Mode.Encrypt,
                        resizedKey(encryptionKey_C2S, cipher_C2S.getBlockSize(), hash, kex.getK(), kex.getH()),
                        initialIV_C2S);

        final Cipher cipher_S2C = Factory.Named.Util.create(this.config.getCipherFactories(),
                                                            negotiatedAlgs.getServer2ClientCipherAlgorithm());
        cipher_S2C.init(Cipher.Mode.Decrypt,
                        resizedKey(encryptionKey_S2C, cipher_S2C.getBlockSize(), hash, kex.getK(), kex.getH()),
                        initialIV_S2C);

        final MAC mac_C2S = Factory.Named.Util.create(this.config.getMACFactories(), negotiatedAlgs
                                                                                                   .getClient2ServerMACAlgorithm());
        mac_C2S.init(resizedKey(integrityKey_C2S, mac_C2S.getBlockSize(), hash, kex.getK(), kex.getH()));

        final MAC mac_S2C = Factory.Named.Util.create(this.config.getMACFactories(),
                                                      negotiatedAlgs.getServer2ClientMACAlgorithm());
        mac_S2C.init(resizedKey(integrityKey_S2C, mac_S2C.getBlockSize(), hash, kex.getK(), kex.getH()));

        final Compression compression_S2C =
                Factory.Named.Util.create(this.config.getCompressionFactories(),
                                          negotiatedAlgs.getServer2ClientCompressionAlgorithm());
        final Compression compression_C2S =
                Factory.Named.Util.create(this.config.getCompressionFactories(),
                                          negotiatedAlgs.getClient2ServerCompressionAlgorithm());

        // TODO compression

        SshAlgoConfig algoCfg = new SshAlgoConfig(cipher_C2S, mac_C2S);
        this.chan.pipeline().fireUserEventTriggered(algoCfg);
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        // TODO if stuff add key / algo
        if (evt instanceof SshAlgoConfig) {
            SshAlgoConfig cfgAlgo = (SshAlgoConfig) evt;

        }
    }

    private void ensureKexOngoing() throws TransportException {
        if (!this.kexOngoing.get()) {
            throw new TransportException(DisconnectReason.PROTOCOL_ERROR,
                                         "Key exchange packet received when key exchange was not ongoing");
        }
    }

    /**
     * Private method used while putting new keys into use that will resize the key used to initialize the cipher to the
     * needed length.
     *
     * @param E         the key to resize
     * @param blockSize the cipher block size
     * @param hash      the hash algorithm
     * @param K         the key exchange K parameter
     * @param H         the key exchange H parameter
     *
     * @return the resized key
     */
    private static byte[] resizedKey(byte[] E, int blockSize, Digest hash, BigInteger K, byte[] H) {
        while (blockSize > E.length) {
            Buffer.PlainBuffer buffer = new Buffer.PlainBuffer().putMPInt(K).putRawBytes(H).putRawBytes(E);
            hash.update(buffer.array(), 0, buffer.available());
            byte[] foo = hash.digest();
            byte[] bar = new byte[E.length + foo.length];
            System.arraycopy(E, 0, bar, 0, E.length);
            System.arraycopy(foo, 0, bar, E.length, foo.length);
            E = bar;
        }
        return E;
    }

    private static void ensureReceivedMatchesExpected(Message got, Message expected) throws TransportException {
        if (got != expected) {
            throw new TransportException(DisconnectReason.PROTOCOL_ERROR, "Was expecting " + expected);
        }
    }

    private static enum Expected {
        /** we have sent or are sending KEXINIT, and expect the server's KEXINIT */
        KEXINIT,
        /** we are expecting some followup data as part of the exchange */
        FOLLOWUP,
        /** we are expecting SSH_MSG_NEWKEYS */
        NEWKEYS,
    }

}
