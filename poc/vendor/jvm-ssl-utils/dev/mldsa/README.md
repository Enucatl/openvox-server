# Isolated ML-DSA-44 issuer experiment

From the repository root:

```sh
docker build -t openvox-ssl-utils-mldsa:poc -f dev/mldsa/Dockerfile .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --memory 1g --cpus 2 openvox-ssl-utils-mldsa:poc
```

The image compiles the checked-out Java sources with `--release 17`, using
checksum-verified BC 1.86 dependencies. It runs the standalone assertion test on
Java 25. Tests generate keys in memory. No production packages or keys are used.

The check covers RSA, JDK ML-DSA-44 and BC ML-DSA-44 keys: private/public PEM
roundtrips, certificate issuance and verification, certificate/public-key
matching across providers, rejection of unrelated issuer keys, CSR signature
validation including a mismatched key pair, initial CRLs, single and multiple
revocations, retained revocations, CRL numbers and updated CRL signatures.
A CA certificate is selected from a chain using its PKCS8 private key; an
unrelated private key is rejected. This covers RSA PKCS8 and ML-DSA seed-only
and expanded encodings using BC's maintained public-key derivation API.
A mixed-algorithm subject verifies that the issuer determines the signature.
RSA certificate/CRL SHA-256 and CSR SHA-1 defaults remain unchanged.

Pass an imported CA certificate's `getSubjectX500Principal()` to `signCertificate`
(or Clojure `sign-certificate`) to preserve its issuer name's exact DER encoding.
The existing string API keeps its original behavior. The standalone test covers
a PrintableString CA name, including unchanged textual subject output.

The image also contains `/test/ssl-utils-3.7.2-SNAPSHOT-mldsa.jar`, containing
production Java classes and Clojure source for local PoC integration. This is a
standalone development artifact, not a Leiningen release. It does not bundle BC
or other dependencies. Put it before the packaged library on the classpath or
replace that library in an isolated test image. Use compatible BC 1.86 jars.

This check does not run the upstream Clojure suite or exercise Java 17/21, FIPS runtime,
TLS or server enrollment. It adds no key-generation setting: imported ML-DSA-44
keys determine signing while RSA key generation remains the default.
