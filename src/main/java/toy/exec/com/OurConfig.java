package toy.exec.com;

import com.hierynomus.sshj.signature.SignatureEdDSA;
import com.hierynomus.sshj.transport.cipher.BlockCiphers;
import com.hierynomus.sshj.transport.cipher.StreamCiphers;
import com.hierynomus.sshj.userauth.keyprovider.OpenSSHKeyV1KeyFile;
import toy.SftpUploadToy;
import java.io.IOException;
import java.util.*;
import net.schmizz.keepalive.KeepAliveProvider;
import net.schmizz.sshj.ConfigImpl;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.signature.SignatureDSA;
import net.schmizz.sshj.signature.SignatureECDSA;
import net.schmizz.sshj.signature.SignatureRSA;
import net.schmizz.sshj.transport.cipher.*;
import net.schmizz.sshj.transport.compression.NoneCompression;
import net.schmizz.sshj.transport.kex.*;
import net.schmizz.sshj.transport.mac.*;
import net.schmizz.sshj.transport.random.BouncyCastleRandom;
import net.schmizz.sshj.transport.random.JCERandom;
import net.schmizz.sshj.transport.random.SingletonRandomFactory;
import net.schmizz.sshj.userauth.keyprovider.OpenSSHKeyFile;
import net.schmizz.sshj.userauth.keyprovider.PKCS5KeyFile;
import net.schmizz.sshj.userauth.keyprovider.PKCS8KeyFile;
import net.schmizz.sshj.userauth.keyprovider.PuTTYKeyFile;
import org.slf4j.Logger;

public class OurConfig extends ConfigImpl {

    private Logger log;

    public OurConfig() {
        setLoggerFactory(LoggerFactory.DEFAULT);
        setVersion(readVersionFromProperties());
        final boolean bouncyCastleRegistered = SecurityUtils.isBouncyCastleRegistered();
        initKeyExchangeFactories(bouncyCastleRegistered);
        initRandomFactory(bouncyCastleRegistered);
        initFileKeyProviderFactories(bouncyCastleRegistered);
        initCipherFactories();
        initCompressionFactories();
        initMACFactories();
        initSignatureFactories();
        setKeepAliveProvider(KeepAliveProvider.HEARTBEAT);
    }

    private String readVersionFromProperties() {
        try {
            Properties properties = new Properties();
            properties.load(OurConfig.class.getClassLoader().getResourceAsStream("sshj.properties"));
            String property = properties.getProperty("sshj.version");
            return "SSHJ_" + property.replace('-', '_'); // '-' is a disallowed character, see RFC-4253#section-4.2
        } catch (IOException e) {
            log.error("Could not read the sshj.properties file, returning an 'unknown' version as fallback.");
            return "SSHJ_VERSION_UNKNOWN";
        }
    }

    @Override
    public void setLoggerFactory(LoggerFactory loggerFactory) {
        super.setLoggerFactory(loggerFactory);
        log = loggerFactory.getLogger(getClass());
    }

    protected void initKeyExchangeFactories(boolean bouncyCastleRegistered) {
        if (bouncyCastleRegistered) {
            setKeyExchangeFactories(
                                    new Curve25519SHA256.Factory(),
                                    new DHGexSHA256.Factory(),
                                    new ECDHNistP.Factory521(),
                                    new ECDHNistP.Factory384(),
                                    new ECDHNistP.Factory256(),
                                    new DHGexSHA1.Factory(),
                                    new DHG14.Factory(),
                                    new DHG1.Factory());
        } else {
            setKeyExchangeFactories(new DHG1.Factory(), new DHGexSHA1.Factory());
        }
    }

    protected void initRandomFactory(boolean bouncyCastleRegistered) {
        setRandomFactory(new SingletonRandomFactory(bouncyCastleRegistered
                                                                          ? new BouncyCastleRandom.Factory() : new JCERandom.Factory()));
    }

    protected void initFileKeyProviderFactories(boolean bouncyCastleRegistered) {
        if (bouncyCastleRegistered) {
            setFileKeyProviderFactories(
                                        new OpenSSHKeyV1KeyFile.Factory(),
                                        new PKCS8KeyFile.Factory(),
                                        new PKCS5KeyFile.Factory(),
                                        new OpenSSHKeyFile.Factory(),
                                        new PuTTYKeyFile.Factory());
        }
    }

    protected void initCipherFactories() {
        List<Factory.Named<Cipher>> avail = new LinkedList<Factory.Named<Cipher>>(Arrays.<Factory.Named<Cipher>> asList(
                                                                                                                        new AES128CTR.Factory(),
                                                                                                                        new AES192CTR.Factory(),
                                                                                                                        new AES256CTR.Factory(),
                                                                                                                        new AES128CBC.Factory(),
                                                                                                                        new AES192CBC.Factory(),
                                                                                                                        new AES256CBC.Factory(),
                                                                                                                        new TripleDESCBC.Factory(),
                                                                                                                        new BlowfishCBC.Factory(),
                                                                                                                        BlockCiphers.BlowfishCTR(),
                                                                                                                        BlockCiphers.Cast128CBC(),
                                                                                                                        BlockCiphers.Cast128CTR(),
                                                                                                                        BlockCiphers.IDEACBC(),
                                                                                                                        BlockCiphers.IDEACTR(),
                                                                                                                        BlockCiphers.Serpent128CBC(),
                                                                                                                        BlockCiphers.Serpent128CTR(),
                                                                                                                        BlockCiphers.Serpent192CBC(),
                                                                                                                        BlockCiphers.Serpent192CTR(),
                                                                                                                        BlockCiphers.Serpent256CBC(),
                                                                                                                        BlockCiphers.Serpent256CTR(),
                                                                                                                        BlockCiphers.TripleDESCTR(),
                                                                                                                        BlockCiphers.Twofish128CBC(),
                                                                                                                        BlockCiphers.Twofish128CTR(),
                                                                                                                        BlockCiphers.Twofish192CBC(),
                                                                                                                        BlockCiphers.Twofish192CTR(),
                                                                                                                        BlockCiphers.Twofish256CBC(),
                                                                                                                        BlockCiphers.Twofish256CTR(),
                                                                                                                        BlockCiphers.TwofishCBC(),
                                                                                                                        StreamCiphers.Arcfour(),
                                                                                                                        StreamCiphers.Arcfour128(),
                                                                                                                        StreamCiphers.Arcfour256())
                );

        boolean warn = false;
        // Ref. https://issues.apache.org/jira/browse/SSHD-24
        // "AES256 and AES192 requires unlimited cryptography extension"
        for (Iterator<Factory.Named<Cipher>> i = avail.iterator(); i.hasNext();) {
            final Factory.Named<Cipher> f = i.next();
            try {
                final Cipher c = f.create();
                final byte[] key = new byte[c.getBlockSize()];
                final byte[] iv = new byte[c.getIVSize()];
                c.init(Cipher.Mode.Encrypt, key, iv);
            } catch (Exception e) {
                warn = true;
                log.warn(e.getCause().getMessage());
                i.remove();
            }
        }
        if (warn)
            log.warn("Disabling high-strength ciphers: cipher strengths apparently limited by JCE policy");

        setCipherFactories(avail);
        log.debug("Available cipher factories: {}", avail);
    }

    protected void initSignatureFactories() {
        setSignatureFactories(
                              new SignatureECDSA.Factory(),
                              new SignatureRSA.Factory(),
                              new SignatureDSA.Factory(),
                              new SignatureEdDSA.Factory());
    }

    protected void initMACFactories() {
        setMACFactories(
                        new HMACSHA1.Factory(),
                        new HMACSHA196.Factory(),
                        new HMACMD5.Factory(),
                        new HMACMD596.Factory(),
                        new HMACSHA2256.Factory(),
                        new HMACSHA2512.Factory());
    }

    protected void initCompressionFactories() {
        setCompressionFactories(new NoneCompression.Factory());
    }
}
