import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class ArtifactProbe {
    public static void main(String[] args) throws Exception {
        var context = SSLContext.getInstance("TLS");
        if (!context.getProvider().getName().equals("BCJSSE")
                || !KeyManagerFactory.getDefaultAlgorithm().equals("PKIX")
                || !TrustManagerFactory.getDefaultAlgorithm().equals("PKIX")) {
            throw new AssertionError("BCJSSE and PKIX startup configuration required");
        }
        context.init(null, null, null);
        System.out.println(context.getProvider());
        System.out.println(context.createSSLEngine().getClass());
        System.out.println("ARTIFACT_ENGINE_PASS");
    }
}
