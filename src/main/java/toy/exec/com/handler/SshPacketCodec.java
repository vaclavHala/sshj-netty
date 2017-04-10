package toy.exec.com.handler;

import toy.exec.com.handler.SSHPacketWrapper;
import toy.exec.com.handler.SshAlgoConfig;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import lombok.extern.slf4j.Slf4j;
import net.schmizz.sshj.common.*;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.cipher.Cipher;
import net.schmizz.sshj.transport.cipher.NoneCipher;
import net.schmizz.sshj.transport.mac.MAC;
import net.schmizz.sshj.transport.random.Random;

/**
 * From RFC 4253, p. 6
 * Each packet is in the following format:
 *     uint32    packet_length
 *     byte      padding_length
 *     byte[n1]  payload; n1 = packet_length - padding_length - 1
 *     byte[n2]  random padding; n2 = padding_length
 *     byte[m]   mac (Message Authentication Code - MAC); m = mac_length
 */
@Slf4j
public class SshPacketCodec extends ChannelDuplexHandler {

    private static final int MAX_PACKET_LEN = 256 * 1024;

    private final Random prng;

    private Cipher cipher;
    private MAC mac;

    private int cipherSize = 8;
    private long seq = -1;
    private boolean authed;

    private int packetLength = -1;
    private final SSHPacket inputBuffer = new SSHPacket();
    private byte[] macResult;

    public SshPacketCodec(Random prng) {
        this.prng = prng;
        // before we nogotiate algos messages are in plain text
        this.cipher = new NoneCipher();
        this.mac = null;
    }

    // FIXME for simplicity we never rekex yet
    // TODO compression as separate handler?

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {

        SSHPacket buffer = (SSHPacket) msg;

        log.debug("Encoding packet: {}", buffer);

        final int payloadSize = buffer.available();

        // Compute padding length
        int padLen = -(payloadSize + 5) & cipherSize - 1;
        if (padLen < cipherSize)
            padLen += cipherSize;

        final int startOfPacket = buffer.rpos() - 5;
        final int packetLen = payloadSize + 1 + padLen;

        // Put packet header
        buffer.wpos(startOfPacket);
        buffer.putUInt32(packetLen);
        buffer.putByte((byte) padLen);

        // Now wpos will mark end of padding
        buffer.wpos(startOfPacket + 5 + payloadSize + padLen);
        // Fill padding
        prng.fill(buffer.array(), buffer.wpos() - padLen, padLen);

        seq = seq + 1 & 0xffffffffL;

        if (mac != null) {
            putMAC(buffer, startOfPacket, buffer.wpos());
        }

        cipher.update(buffer.array(), startOfPacket, 4 + packetLen);

        buffer.rpos(startOfPacket); // Make ready-to-read

        ByteBuf buf = Unpooled.wrappedBuffer(buffer.array(), 0, buffer.available());
        log.warn("Encoded ABR {}", buf);
        ctx.write(buf, promise);
    }

    private void putMAC(SSHPacket buffer, int startOfPacket, int endOfPadding) {
        buffer.wpos(endOfPadding + mac.getBlockSize());
        mac.update(seq);
        mac.update(buffer.array(), startOfPacket, endOfPadding);
        mac.doFinal(buffer.array(), endOfPadding);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!(msg instanceof ByteBuf)) {
            //e.g. server ident is handled specially and just passes through here
            ctx.fireChannelRead(msg);
            return;
        }

        ByteBuf buf = (ByteBuf) msg;
        if (buf.hasArray()) {
            this.inputBuffer.putRawBytes(buf.array(), 0, buf.readableBytes());
        } else {
            buf.forEachByte(b -> {
                this.inputBuffer.putByte(b);
                return true;
            });
        }

        int packetLength = decryptLength();

        //            assert inputBuffer.rpos() == 4 : "packet length read";

        //            need = packetLength + (mac != null ? mac.getBlockSize() : 0) - inputBuffer.available();

        decryptPayload(inputBuffer.array());

        seq = seq + 1 & 0xffffffffL;

        if (mac != null) {
            checkMAC(inputBuffer.array());
        }

        // Exclude the padding & MAC
        inputBuffer.wpos(packetLength + 4 - inputBuffer.readByte());

        log.trace("Received packet #{}: {}", seq, inputBuffer.printHex());
        ctx.fireChannelRead(new SSHPacketWrapper(inputBuffer));
        //            packetHandler.handle(plain.readMessageID(), plain); // Process the decoded packet

        inputBuffer.clear();
        packetLength = -1;
    }

    private void checkMAC(final byte[] data)
                                            throws TransportException {
        mac.update(seq); // seq num
        mac.update(data, 0, packetLength + 4); // packetLength+4 = entire packet w/o mac
        mac.doFinal(macResult, 0); // compute
        // Check against the received MAC
        if (!ByteArrayUtils.equals(macResult, 0, data, packetLength + 4, mac.getBlockSize()))
            throw new TransportException(DisconnectReason.MAC_ERROR, "MAC Error");
    }

    private int decryptLength() throws TransportException {
        cipher.update(inputBuffer.array(), 0, cipherSize);

        final int len; // Read packet length
        try {
            len = inputBuffer.readUInt32AsInt();
        } catch (Buffer.BufferException be) {
            throw new TransportException(be);
        }

        if (isInvalidPacketLength(len)) { // Check packet length validity
            log.error("Error decoding packet (invalid length) {}", inputBuffer.printHex());
            throw new TransportException(DisconnectReason.PROTOCOL_ERROR, "invalid packet length: " + len);
        }

        return len;
    }

    private static boolean isInvalidPacketLength(int len) {
        return len < 5 || len > MAX_PACKET_LEN;
    }

    private void decryptPayload(final byte[] data) {
        cipher.update(data, cipherSize, packetLength + 4 - cipherSize);
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof SshAlgoConfig) {
            SshAlgoConfig cfg = (SshAlgoConfig) evt;
            this.setAlgorithms(cfg.cipher, cfg.mac);
        }

        ctx.fireUserEventTriggered(evt);
    }

    public void setAlgorithms(Cipher cipher, MAC mac) {
        this.cipher = cipher;
        this.mac = mac;
        this.cipherSize = cipher.getIVSize();

        this.macResult = new byte[mac.getBlockSize()];
    }

}
