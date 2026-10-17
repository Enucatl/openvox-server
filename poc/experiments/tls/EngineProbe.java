import javax.net.ssl.SSLContext;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
public class EngineProbe {
  public static void main(String[] args) throws Exception {
    var provider = new BouncyCastleJsseProvider(new BouncyCastleProvider());
    var ctx = SSLContext.getInstance("TLS", provider);
    ctx.init(null, null, null);
    System.out.println("ENGINE_CLASS " + Class.forName("org.bouncycastle.jsse.provider.SSLEngineUtil").getResource("SSLEngineUtil.class"));
    System.out.println("ENGINE_CREATED " + ctx.createSSLEngine().getClass());
  }
}
