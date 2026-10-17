import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import clojure.java.api.Clojure;
import clojure.lang.*;
import com.puppetlabs.ssl_utils.SSLUtils;
import com.puppetlabs.trapperkeeper.services.webserver.jetty.utils.InternalSslContextFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.util.Callback;

public class JettyTest {
  static Keyword kw(String name) { return Keyword.intern(name); }
  public static void main(String[] args) throws Exception {
    Path dir = Path.of(args[0]);
    System.out.println("MULTI_RELEASE_SETTING " + System.getProperty("jdk.util.jar.enableMultiRelease", "default"));
    System.out.println("TLS_JAR " + BouncyCastleJsseProvider.class.getProtectionDomain().getCodeSource().getLocation());
    System.setProperty("jdk.tls.server.SignatureSchemes", "mldsa44,rsa_pss_rsae_sha256,rsa_pss_pss_sha256,ecdsa_secp256r1_sha256,ed25519,rsa_pkcs1_sha256");
    System.setProperty("org.bouncycastle.jsse.server.SignatureSchemesCert", "mldsa44,rsa_pkcs1_sha256,rsa_pss_rsae_sha256,rsa_pss_pss_sha256,ecdsa_secp256r1_sha256,ed25519");
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
    Security.insertProviderAt(new BouncyCastleJsseProvider("BC"), 1);
    Security.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX");
    Security.setProperty("ssl.TrustManagerFactory.algorithm", "PKIX");
    Clojure.var("clojure.core", "require").invoke(Clojure.read("puppetlabs.trapperkeeper.services.webserver.jetty-core"));
    Map<String,Object> stores = SSLUtils.pemsToKeyAndTrustStores(
      new StringReader(Files.readString(dir.resolve("server.pem")) + Files.readString(dir.resolve("sub.pem")) + Files.readString(dir.resolve("root.pem"))),
      Files.newBufferedReader(dir.resolve("server.key")), Files.newBufferedReader(dir.resolve("root.pem")));
    var config = RT.map(
      kw("keystore-config"), RT.map(kw("keystore"), stores.get("keystore"), kw("key-password"), stores.get("keystore-pw"), kw("truststore"), stores.get("truststore")),
      kw("client-auth"), kw("need"), kw("ssl-crl-path"), dir.resolve("active.crl").toAbsolutePath().toString(),
      kw("protocols"), PersistentVector.create("TLSv1.3"),
      kw("cipher-suites"), PersistentVector.create("TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"),
      kw("allow-renegotiation"), false, kw("sni-required"), false);
    InternalSslContextFactory ssl = (InternalSslContextFactory)Clojure.var("puppetlabs.trapperkeeper.services.webserver.jetty-core", "ssl-context-server-factory").invoke(config);
    org.eclipse.jetty.server.Server server = new org.eclipse.jetty.server.Server();
    HttpConfiguration http = new HttpConfiguration(); http.addCustomizer(new SecureRequestCustomizer());
    ServerConnector connector = new ServerConnector(server, new SslConnectionFactory(ssl, "http/1.1"), new HttpConnectionFactory(http));
    connector.setHost("127.0.0.1"); connector.setPort(0); server.addConnector(connector);
    server.setHandler(new Handler.Abstract() {
      public boolean handle(Request request, Response response, Callback callback) {
        response.setStatus(200); response.write(true, ByteBuffer.wrap("pong\n".getBytes()), callback); return true;
      }
    });
    try {
      server.start();
      System.out.println("JETTY " + org.eclipse.jetty.util.Jetty.VERSION + " PROVIDER " + ssl.getSslContext().getProvider() + " CLIENT_AUTH " + ssl.getNeedClientAuth() + " REVOCATION " + ssl.isValidatePeerCerts());
      Files.writeString(dir.resolve("ready"), Integer.toString(connector.getLocalPort()));
      BufferedReader control = new BufferedReader(new InputStreamReader(System.in));
      if (!"reload".equals(control.readLine())) throw new IOException("expected reload command");
      Files.copy(dir.resolve("revoked.crl"), dir.resolve("active.crl"), StandardCopyOption.REPLACE_EXISTING);
      ssl.reload();
      System.out.println("CRL_RELOADED"); Files.writeString(dir.resolve("reloaded"), "yes");
      if (!"stop".equals(control.readLine())) throw new IOException("expected stop command");
    } finally { server.stop(); }
  }
}
