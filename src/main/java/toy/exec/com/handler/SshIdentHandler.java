package toy.exec.com.handler;

import io.netty.buffer.ByteBuf;
import static io.netty.buffer.ByteBufUtil.hexDump;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.ByteToMessageDecoder.Cumulator;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import static java.nio.charset.StandardCharsets.UTF_8;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

/**
 * Reads up to and including \r\n from input,
 * interprets that as server ident and sends the rest as regular buf.
 * Removes itself from pipe after receiving the ident.
 */

@Slf4j
public class SshIdentHandler extends ChannelDuplexHandler {

    // needs to end by \r\n, defined by protocol
    private final String clientIdent = "SSH-2.0-SSHJ_0.19.1\r\n";

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        ctx.fireChannelActive();
        log.debug("Sending our ident: <{}>", clientIdent);
        ctx.writeAndFlush(Unpooled.wrappedBuffer(this.clientIdent.getBytes(UTF_8)));
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        ByteBuf buf = (ByteBuf) msg;
        String serverIdident = buf.toString(UTF_8);
        log.debug("Server Ident: <{}>", serverIdident);
        ctx.pipeline().remove(this);
        ctx.fireChannelRead(new SshIdentInfo(this.clientIdent, serverIdident));
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        // TODO buffer all here, release when received server ident
        log.error("early write {}", hexDump((ByteBuf) msg));
    }

    @ToString
    @RequiredArgsConstructor
    public static class SshIdentInfo {

        public final String clientId;
        public final String serverId;
    }

}
