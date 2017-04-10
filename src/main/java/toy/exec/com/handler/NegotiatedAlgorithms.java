package toy.exec.com.handler;

public final class NegotiatedAlgorithms {

    private final String kex;
    private final String sig;
    private final String c2sCipher;
    private final String s2cCipher;
    private final String c2sMAC;
    private final String s2cMAC;
    private final String c2sComp;
    private final String s2cComp;

    public NegotiatedAlgorithms(String kex, String sig, String c2sCipher, String s2cCipher, String c2sMAC, String s2cMAC, String c2sComp, String s2cComp) {
        this.kex = kex;
        this.sig = sig;
        this.c2sCipher = c2sCipher;
        this.s2cCipher = s2cCipher;
        this.c2sMAC = c2sMAC;
        this.s2cMAC = s2cMAC;
        this.c2sComp = c2sComp;
        this.s2cComp = s2cComp;
    }

    public String getKeyExchangeAlgorithm() {
        return kex;
    }

    public String getSignatureAlgorithm() {
        return sig;
    }

    public String getClient2ServerCipherAlgorithm() {
        return c2sCipher;
    }

    public String getServer2ClientCipherAlgorithm() {
        return s2cCipher;
    }

    public String getClient2ServerMACAlgorithm() {
        return c2sMAC;
    }

    public String getServer2ClientMACAlgorithm() {
        return s2cMAC;
    }

    public String getClient2ServerCompressionAlgorithm() {
        return c2sComp;
    }

    public String getServer2ClientCompressionAlgorithm() {
        return s2cComp;
    }

    @Override
    public String toString() {
        return ("[ " +
                "kex=" + kex + "; " +
                "sig=" + sig + "; " +
                "c2sCipher=" + c2sCipher + "; " +
                "s2cCipher=" + s2cCipher + "; " +
                "c2sMAC=" + c2sMAC + "; " +
                "s2cMAC=" + s2cMAC + "; " +
                "c2sComp=" + c2sComp + "; " +
                "s2cComp=" + s2cComp + " ]");
    }

}
