import java.security.Security;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class StartupProbe {
    public static void main(String[] args) throws Exception {
        var context = SSLContext.getInstance("TLS");
        System.out.println("TLS_PROVIDER " + context.getProvider());
        System.out.println("KEY_MANAGER " + KeyManagerFactory.getDefaultAlgorithm());
        System.out.println("TRUST_MANAGER " + TrustManagerFactory.getDefaultAlgorithm());
        for (var provider : Security.getProviders()) {
            System.out.println("PROVIDER " + provider);
            System.out.println("PROVIDER_SOURCE " + provider.getName() + " " + provider.getClass().getProtectionDomain().getCodeSource());
        }
        if (args[0].equals("bc") && (!context.getProvider().getName().equals("BCJSSE")
                || !KeyManagerFactory.getDefaultAlgorithm().equals("PKIX")
                || !TrustManagerFactory.getDefaultAlgorithm().equals("PKIX"))) {
            throw new IllegalStateException("BCJSSE/PKIX startup configuration was not selected");
        }
        if (args[0].equals("default") && !context.getProvider().getName().equals("SunJSSE")) {
            throw new IllegalStateException("Default-provider control did not select SunJSSE");
        }
    }
}
