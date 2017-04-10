package toy.exec.com.handler;

import io.netty.buffer.ByteBuf;
import static io.netty.buffer.ByteBufUtil.hexDump;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.LineBasedFrameDecoder;
import lombok.extern.slf4j.Slf4j;

/**
 * First message in the stream is server ident which, unlike other messages,
 * is delimited by \r\n instead of having frame length.
 * This handler decodes start of stream using \r\n, then sends rest of cumulated
 * bytes as regular message and removes itself from the pipe
 */
@Slf4j
public class SshIdentDecoder extends LineBasedFrameDecoder {

    private boolean identFound = false;

    public SshIdentDecoder() {
        super(Integer.MAX_VALUE, false, true);
        this.setSingleDecode(true);
    }

    @Override
    protected Object decode(ChannelHandlerContext ctx, ByteBuf buffer) throws Exception {
        Object decoded = super.decode(ctx, buffer);
        if (decoded != null) {
            // cant remove ourselves here immediately, because then rest of cumulated stream
            // would go before the ident itself (ident is sent after this method ends,
            // rest from within remove callback)
            this.identFound = true;
        }
        return decoded;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        super.channelRead(ctx, msg);
        if (this.identFound) {
            log.debug("Server ident found, removing ident delimiter decoder");
            // by now we have sent the decoded ident
            ctx.pipeline().remove(this);
        }
    }
}
