package toy.exec.com.handler;

import lombok.RequiredArgsConstructor;
import lombok.ToString;
import net.schmizz.sshj.transport.cipher.Cipher;
import net.schmizz.sshj.transport.mac.MAC;

@ToString
@RequiredArgsConstructor
public class SshAlgoConfig {

    public final Cipher cipher;
    public final MAC mac;
}
