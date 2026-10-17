package com.puppetlabs.ssl_utils;

import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;

/** Standalone cryptographic regression check: run with java -ea. */
public class IssuerSigningTest {
    private static final String MLDSA44 = "2.16.840.1.101.3.4.3.17";

    private static String pem(Object value) throws Exception {
        StringWriter writer = new StringWriter();
        SSLUtils.writeToPEM(value, writer);
        return writer.toString();
    }

    private static KeyPair keys(String algorithm, String provider) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, provider);
        if (algorithm.equals("RSA")) generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(KeyPair issuer, KeyPair subject, int serial) throws Exception {
        return SSLUtils.signCertificate("CN=issuer", issuer.getPrivate(), BigInteger.valueOf(serial),
                new Date(System.currentTimeMillis() - 60000),
                new Date(System.currentTimeMillis() + 3600000), "CN=leaf", subject.getPublic(), null);
    }

    private static void checkPrivateKeySelection(PrivateKey privateKey, KeyPair issuer, KeyPair other) throws Exception {
        String pkcs8 = pem(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
        assert pkcs8.contains("BEGIN PRIVATE KEY");
        assert Arrays.equals(issuer.getPublic().getEncoded(),
                SSLUtils.pemToPublicKey(new StringReader(pkcs8)).getEncoded());
        X509Certificate expected = certificate(issuer, issuer, 5);
        String chain = pem(certificate(other, other, 6)) + pem(expected);
        assert expected.equals(SSLUtils.pemToCaCert(new StringReader(chain), new StringReader(pkcs8)));
        try {
            SSLUtils.pemToCaCert(new StringReader(pem(expected)),
                    new StringReader(pem(new PemObject("PRIVATE KEY", other.getPrivate().getEncoded()))));
            throw new AssertionError("Certificate chain accepted an unrelated private key");
        } catch (IllegalArgumentException expectedMismatch) {
            assert expectedMismatch.getMessage().contains("does not contain a certificate that matches");
        }
    }

    private static void checkIssuerEncoding(KeyPair issuer, String signatureAlgorithm) throws Exception {
        X500Name name = new X500NameBuilder().addRDN(BCStyle.CN, new DERPrintableString("Printable CA")).build();
        Date before = new Date(System.currentTimeMillis() - 60000);
        Date after = new Date(System.currentTimeMillis() + 3600000);
        X509Certificate ca = new JcaX509CertificateConverter().getCertificate(new X509v3CertificateBuilder(
                name, BigInteger.ONE, before, after, name,
                SubjectPublicKeyInfo.getInstance(issuer.getPublic().getEncoded()))
                .build(new JcaContentSignerBuilder(signatureAlgorithm).build(issuer.getPrivate())));
        X509Certificate issued = SSLUtils.signCertificate(ca.getSubjectX500Principal(), issuer.getPrivate(),
                BigInteger.TWO, before, after, "CN=leaf", issuer.getPublic(), null);
        assert Arrays.equals(ca.getSubjectX500Principal().getEncoded(), issued.getIssuerX500Principal().getEncoded());
        issued.verify(issuer.getPublic());
        assert "CN=Printable CA".equals(SSLUtils.getSubjectFromX509Certificate(ca));
    }

    private static void check(String algorithm, String provider) throws Exception {
        KeyPair issuer = keys(algorithm, provider);
        KeyPair leaf = keys(algorithm, provider);
        KeyPair other = keys(algorithm, provider);
        String signatureOID = algorithm.equals("RSA") ? "1.2.840.113549.1.1.11" : MLDSA44;
        String csrOID = algorithm.equals("RSA") ? "1.2.840.113549.1.1.5" : MLDSA44;
        PrivateKey imported = SSLUtils.pemToPrivateKey(new StringReader(pem(issuer.getPrivate())));
        issuer = new KeyPair(issuer.getPublic(), imported);
        checkIssuerEncoding(issuer, algorithm.equals("RSA") ? "SHA256withRSA" : "ML-DSA-44");
        checkPrivateKeySelection(issuer.getPrivate(), issuer, other);
        if (algorithm.equals("ML-DSA-44")) {
            MLDSAPrivateKey bcKey = (MLDSAPrivateKey) new JcaPEMKeyConverter()
                    .setProvider(new BouncyCastleProvider())
                    .getPrivateKey(PrivateKeyInfo.getInstance(issuer.getPrivate().getEncoded()));
            checkPrivateKeySelection(bcKey.getPrivateKey(true), issuer, other);
            checkPrivateKeySelection(bcKey.getPrivateKey(false), issuer, other);
        }
        assert Arrays.equals(issuer.getPublic().getEncoded(),
                SSLUtils.pemToPublicKey(new StringReader(pem(issuer.getPublic()))).getEncoded());

        X509Certificate cert = certificate(issuer, leaf, 1);
        assert signatureOID.equals(cert.getSigAlgOID());
        cert.verify(issuer.getPublic());
        try {
            cert.verify(other.getPublic());
            throw new AssertionError("Certificate accepted an unrelated issuer key");
        } catch (SignatureException expected) { }
        X509Certificate parsedCert = SSLUtils.pemToCert(new StringReader(pem(cert)));
        parsedCert.verify(issuer.getPublic());
        assert SSLUtils.certMatchesPubKey(parsedCert, leaf.getPublic());
        assert !SSLUtils.certMatchesPubKey(parsedCert, other.getPublic());

        PKCS10CertificationRequest csr = SSLUtils.generateCertificateRequest(leaf, "CN=leaf", null, null);
        assert csrOID.equals(csr.getSignatureAlgorithm().getAlgorithm().getId());
        assert SSLUtils.isSignatureValid(csr);
        PKCS10CertificationRequest mismatched = SSLUtils.generateCertificateRequest(
                new KeyPair(other.getPublic(), leaf.getPrivate()), "CN=leaf", null, null);
        assert !SSLUtils.isSignatureValid(mismatched);

        X509CRL crl = SSLUtils.generateCRL(new X500Principal("CN=issuer"),
                issuer.getPrivate(), issuer.getPublic());
        assert signatureOID.equals(crl.getSigAlgOID());
        crl.verify(issuer.getPublic());
        assert !SSLUtils.isRevoked(crl, cert);
        X509CRL updated = SSLUtils.revoke(crl, issuer.getPrivate(), issuer.getPublic(), BigInteger.ONE);
        assert signatureOID.equals(updated.getSigAlgOID());
        updated.verify(issuer.getPublic());
        assert SSLUtils.isRevoked(updated, cert);
        assert !SSLUtils.isRevoked(updated, certificate(issuer, leaf, 2));
        X509CRL twice = SSLUtils.revokeMultiple(updated, issuer.getPrivate(), issuer.getPublic(),
                Arrays.asList(BigInteger.valueOf(2), BigInteger.valueOf(3)));
        twice.verify(issuer.getPublic());
        assert SSLUtils.isRevoked(twice, cert);
        assert SSLUtils.isRevoked(twice, certificate(issuer, leaf, 2));
        assert SSLUtils.isRevoked(twice, certificate(issuer, leaf, 3));
        assert BigInteger.valueOf(2).equals(ExtensionsUtils.getExtensionValue(twice, ExtensionsUtils.CRL_NUMBER_OID));
        SSLUtils.pemToCRL(new StringReader(pem(twice))).verify(issuer.getPublic());
        try {
            twice.verify(other.getPublic());
            throw new AssertionError("CRL accepted an unrelated issuer key");
        } catch (SignatureException expected) { }
        System.out.println("PASS " + algorithm + " / " + provider + " / imported " + imported.getAlgorithm()
                + ": PEM/PKCS8 CA selection, wrong private key, certificate, wrong key, CSR, mismatched CSR, initial/update/multi CRL");
    }

    public static void main(String[] args) throws Exception {
        if (!IssuerSigningTest.class.desiredAssertionStatus()) throw new IllegalStateException("Run with -ea");
        check("RSA", "SunRsaSign");
        check("ML-DSA-44", "SUN");
        Security.addProvider(new BouncyCastleProvider());
        check("ML-DSA-44", "BC");
        KeyPair rsa = keys("RSA", "SunRsaSign");
        KeyPair mldsa = keys("ML-DSA-44", "BC");
        X509Certificate mixed = certificate(mldsa, rsa, 4);
        assert MLDSA44.equals(mixed.getSigAlgOID());
        mixed.verify(mldsa.getPublic());
        System.out.println("PASS issuer algorithm selected independently of subject algorithm");
    }
}
