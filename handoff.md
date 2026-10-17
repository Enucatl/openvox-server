# OpenVox ML-DSA-44 implementation handoff

Updated: 17 October 2026.

## Result and goal

The full ML-DSA-44 proof of concept works. The final integration run passed
**87 of 87 assertions**. A real native agent obtained a certificate, applied a
catalog, read a Vault value through Hiera, renewed its certificate, and completed
revocation and identity replacement tests. The agent and server used ML-DSA-44
TLS handshake signatures. They negotiated hybrid post-quantum key exchange.

The next goal is to turn this working implementation into maintainable OpenVox
support. Keep the changes small. Preserve RSA defaults and existing access
controls. Prepare changes that maintainers can review and release separately.
Do not repeat the resolved TLS and certificate-loading investigations.

The required certificate hierarchy is:

```text
Vault ML-DSA-44 root CA
  -> OpenVox ML-DSA-44 subordinate CA
    -> OpenVox server identity
    -> OpenVox agent identities
```

Every public key and certificate signature in this hierarchy uses ML-DSA-44.
OpenVox signs its subordinate CRLs with ML-DSA-44. Vault signs the root CRL.
An ML-DSA root above RSA server or agent keys does not meet this goal.

ML-DSA authenticates identities. ML-KEM contributes to key establishment. Record
these results separately. Do not infer either result from the cipher name.

## Scope and repository state

The working lab is `/opt/docker/openvox-mldsa-lab`. This document is the single
active handoff. Its path is `openvox-server/handoff.md`.

The server fork is [Enucatl/openvox-server](https://github.com/Enucatl/openvox-server).
The upstream project is [OpenVoxProject/openvox-server](https://github.com/OpenVoxProject/openvox-server).
The experimental branch is `poc/mldsa-44`.

Delivery uses two commits on that branch:

1. A temporary PoC commit contains the server changes, tests, reproducer and
   source changes vendored from four local dependency checkouts.
2. A separate commit contains only this handoff.

Only the server repository was newly forked for this work. The other OpenVox
repositories are local upstream clones. `vault-hiera` is a checkout of the
existing `enucatl/vault` module. It is a separate integration, not OpenVox core.
The temporary source snapshot avoids creating four more forks at this stage.
It can be removed when the dependency changes have their own upstream commits.
Do not remove it before those changes are preserved elsewhere.

The sibling working trees retain their changes. The temporary commit stores
copies under `poc/vendor/`. `poc/dependencies.tsv` records their URLs and exact
base commits. That file and this table refer to the source used by the PoC:

| Local checkout | Base commit |
| --- | --- |
| `openvox-server` | `84cbdc0637a93c3280bb8643d4ef0841b0b7ac8d` |
| `openvox` | `e4c91baedaf2ef28ad9b742986b01414b9606d77` |
| `jvm-ssl-utils` | `fecd9e80a1755e07d61708168f27abebf69f9a70` |
| `openvoxserver-ca` | `4bf0c1e25a1e3f99268e26fab1c50caad5c7937a` |
| `vault-hiera` | `1080ac7a84b5e9e3320d6abacd9613085410b176` |

The user authorized the documentation commit, temporary PoC commit and push.
Production changes and external issue reports are outside this task. Preserve
unrelated changes in the control repository.

## What changed and why

The cryptographic algorithms already exist in OpenSSL and Bouncy Castle.
The application changes remove RSA assumptions and handle provider differences.
Enrollment, authorization, catalog processing and revocation keep their existing
application paths.

The implementation/configuration diff has the following size. Counts exclude
tests, documentation, experiment scripts and duplicate vendored copies.
Replaced lines count once as an addition and once as a removal.

| Component | Added / removed lines | Purpose |
| --- | --- | --- |
| Native OpenVox agent | 25 / 10 | Generate and persist ML-DSA keys; build CSRs; support key checks and fingerprints. |
| OpenVox server and build/provider configuration | 43 / 16 | Include BCJSSE; select providers at startup; set correct key usage; preserve issuer encoding. |
| JVM SSL library | 45 / 9 | Select signing algorithms from issuer keys; derive public keys; match keys across providers. |
| Native CA CLI | 27 / 12 | Import generic keys; create CSRs; sign certificates and CRLs with ML-DSA. |
| Vault/Hiera module | 67 / 17 | Use generic native keys and the existing server Java TLS client. |
| **Total** | **207 / 64** | **20 implementation/configuration files.** |

OpenVox and its SSL library account for 140 added and 47 removed lines.
Vault/Hiera accounts for the rest. Its changes are needed only for this module.

### Agent

The explicit setting is `key_type=mldsa44`. RSA remains the default.
Both agent key-generation paths support the setting. Private keys use generic
PKCS8 serialization. CSR signing supplies no separate digest for ML-DSA.
Certificate fingerprints still use SHA-256.

Ruby OpenSSL 4.0.2 cannot identify these keys through `PKey#oid`. The helper reads
the algorithm OID from public-key DER. The ML-DSA-44 OID is
`2.16.840.1.101.3.4.3.17`.

### Server and JVM SSL library

`project.clj` declares regular `bctls-jdk18on` 1.86.2 in the required profiles.
The standalone jar explicitly includes bcpkix and bctls. It includes the modified
sibling `ssl-utils` 3.7.2-SNAPSHOT. Build the two projects together.

`resources/ext/java.security.mldsa` selects BCJSSE and BC before TLS contexts are
created. It selects PKIX key and trust managers. Load it with one equals sign:

```text
-Djava.security.properties=/absolute/path/java.security.mldsa
```

This supplements the JDK security properties. It does not replace them. The
harness separately supplies client/server signature-scheme settings that include
`mldsa44`. See `poc/experiments/enrollment/lifecycle.rb` for the exact JVM arguments.
No new main wrapper or webserver patch was needed.

Certificate and CRL signing now select the algorithm from the issuer key.
ML-DSA leaf certificates have `digitalSignature` key usage without
`keyEncipherment`. RSA behavior remains unchanged.

Issuer names retain their exact ASN.1 DER encoding. The signing API accepts an
`X500Principal` as well as the existing string form. Server signing callers pass
the actual CA principal. This matters for Vault's Go certificate verifier.

Public-key matching compares encoded keys. The JDK calls a parameterized key
`ML-DSA`; BC can call the same key `ML-DSA-44`. A name comparison is insufficient.
The library can derive an ML-DSA public key from a PKCS8 private key when it
selects the matching CA from an imported chain.

### Native CA CLI

The existing `puppetserver ca import` path works with the patched key handling
and signing code. Prepare both configured server private and public key files
with an ML-DSA-44 key pair before import. Otherwise, generation remains RSA.
The tested import supplies the subordinate key, subordinate/root certificates,
subordinate/root CRLs and the `localhost` server SAN. The test then supplies the
server certificate chain to TLS.

See `poc/vendor/openvoxserver-ca/README.md` and the enrollment harness for the
exact preparation and import commands. Use new disposable paths for a test.
Do not apply these commands to a running production CA.

### Vault/Hiera

The module is the existing `enucatl/vault` module, named `vault_secrets` in the
catalog. Its backend is `vault_hiera_hash`.

Native Ruby uses `OpenSSL::PKey.read` instead of RSA-only loading. The server
uses its existing Java SSL/HTTP libraries because JRuby OpenSSL cannot wrap
ML-DSA private keys. Configured CA trust, timeouts and redirect restrictions are
preserved. No replacement backend or new HTTP dependency was added.

## What we tried

| Attempt | Result and resolution |
| --- | --- |
| Java 25 with default SunJSSE | ML-DSA TLS authentication failed with `No available authentication scheme`. Native key loading alone did not establish TLS support. |
| Java 28 EA with SunJSSE | ML-DSA mutual TLS worked in socket tests. This showed that the identity hierarchy was usable. Java 28 is not required by the final PoC. |
| Java 25 with BCJSSE and bctls 1.86 | Socket tests worked. Jetty exposed a multi-release jar linkage defect in TLS engine creation. |
| Java 25 with bctls 1.86.2 | Engine creation and the real Jetty path worked. Keep this corrected dependency. Do not retain the diagnostic `jdk.util.jar.enableMultiRelease=false` workaround. |
| Imported identities with CA service disabled | The packaged service accepted valid ML-DSA clients and rejected missing/untrusted identities and wrong hostnames. This established the service baseline. |
| Local CA enrollment | Agent-generated keys and CSRs, catalog apply, renewal and automatic CRL reload passed 43 assertions. |
| Vault subordinate import | CA selection needed ML-DSA public derivation from PKCS8. The JVM SSL library fix resolved it. |
| Vault authentication with OpenVox-issued leaves | Go rejected a reconstructed issuer name. It differed from the CA subject in ASN.1 string encoding. Passing the CA principal preserved the encoding and resolved it. |
| New SSL library before an old server jar | The server's compiled Clojure wrapper retained the old argument schema. A coordinated clean build against 3.7.2-SNAPSHOT resolved it. The artifact signing probe checks this. |
| Vault listener key loading | Vault accepted seed-only ML-DSA private-key encoding. The fixture converts only its listener key. Agent key persistence is unchanged. |
| Automatic CRL refresh | An early fixture lacked a CRL number. Adding the CRL number and authority key identifier fixed the fixture. No unrelated server workaround was added. |
| TLS observation through RUBYOPT | The package launcher removed RUBYOPT. Explicitly loading the observer with bundled Ruby captured the actual agent handshakes. |
| Final source-built service | The complete Vault-backed lifecycle and TLS observations passed 87 assertions. |

The bctls defect and fix are recorded in
[BC issue 2448](https://github.com/bcgit/bc-java/issues/2448).
Earlier sanitized TLS archives remain in the local `evidence/` directory.
Obsolete runtime directories and copied build contexts are removed during cleanup.

## What the final test proves

The final run used the full source-built server jar alone on the Java classpath.
It did not use a patched SSL library override or external BC jars. Startup probes
identified BC and BCJSSE inside that jar. The agent and CA CLI used the patched
source on official package runtimes.

The test covered:

- Native CA import and matching server/CA key pairs.
- A Vault root and an OpenVox subordinate with ML-DSA keys and signatures.
- Native agent key generation, CSR submission and certificate issuance.
- Exact-name autosign; unauthorized names remain pending.
- CSR name mismatch rejection.
- Real catalog application and a second run with no changes.
- A Hiera lookup through the actual Vault backend. The returned value became
  the content of a managed file.
- Agent certificate login to Vault and scoped ML-DSA application-certificate
  issuance. Other domains and roles were rejected.
- Renewal with the same key and a new serial.
- Automatic CRL expiry refresh, signing and publication.
- Automatic CRL file reload without a server restart.
- Rejection of revoked identities while another valid agent still connects.
- Standard CA authorization. Ordinary agents receive HTTP 403 for CA administration.
- Explicit CRL publication to Vault and rejection of new logins by revoked agents.
- Authorized identity cleanup and enrollment of a new key and serial.
- Continued rejection of the old identity after replacement.
- The same OpenVox lifecycle with RSA and default SunJSSE as a control.

The ancillary application certificate is issued through a separate Vault
root-backed PKI role. It is not an OpenVox agent certificate. The server's Hiera
role can read only the test KV path. The agent's policy can issue only through
its exact test role. Neither receives the bootstrap administrator token.

Existing Vault tokens retain their TTL after certificate revocation. The test
checks new logins. This is Vault behavior, not an OpenVox signing defect.

### Actual agent TLS evidence

The second catalog run recorded two fresh agent connections to the real service
on port 8140 in each configuration:

| Property | ML-DSA / BCJSSE | RSA / SunJSSE control |
| --- | --- | --- |
| Protocol | TLS 1.3 | TLS 1.3 |
| Client CertificateVerify signature | `mldsa44` | `rsa_pss_rsae_sha256` |
| Server CertificateVerify signature | `mldsa44` | `rsa_pss_rsae_sha256` |
| Negotiated key-exchange group | `X25519MLKEM768` | `x25519` |
| Cipher | `TLS_AES_128_GCM_SHA256` | `TLS_AES_128_GCM_SHA256` |
| Session resumed | false | false |

These are handshake values, not certificate signature fields. The test-only
observer uses Ruby OpenSSL's `group`, `sigalg` and `peer_sigalg` accessors after
a successful connection. It changes no TLS settings and records no keys.

`X25519MLKEM768` combines classical X25519 with ML-KEM-768. Thus these measured
agent sessions used post-quantum authentication and hybrid post-quantum key
establishment. See the [OpenSSL group documentation](https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/).
The test asserts both signatures and a recorded group. The JSON records the exact
group above. It does not enforce this group for every possible client.
The separate Java connection from OpenVox to Vault has not had the same
handshake measurements.

## Versions and evidence

| Component | Tested version |
| --- | --- |
| OS | Ubuntu 26.04 amd64 |
| Official agent/server package base | `9.1.0-1+ubuntu26.04` |
| Source-built server | `9.1.1-SNAPSHOT` |
| Source-built JVM SSL library | `3.7.2-SNAPSHOT` |
| Java | `25.0.4.1+1-1~26.04.4` |
| Native Ruby | `4.0.7` |
| Native Ruby OpenSSL extension | `4.0.2` |
| Native agent OpenSSL library | `3.5.9` |
| Fixture OpenSSL CLI | `3.5.5` |
| BC provider/PKIX/util | `1.86` |
| BC TLS | `1.86.2` |
| CA gem package base | `3.3.0` |
| Vault Community | `2.2.0`, commit `2891bfd23893ebd302307050edaf03d871ea8351` |

The final image ID is:

```text
sha256:340cf2108a20f655cf3d99f8bc791c5d62e8aa5afd69fe9c6cc71f71ae88531a
```

The tested server jar SHA-256 is:

```text
144a9ff216e217861d7f1c18b4c8ba94f3ed003fd6e8e7f732403a443e5668ca
```

The tested Vault binary SHA-256 is:

```text
64884404557ee590b43a1842c9cd5a3777895213c34bc10eac05ceb550a4aae7
```

Credential-free results are included in the temporary PoC commit:

- `poc/experiments/enrollment/results.txt`: 87 passing assertions.
- `poc/experiments/enrollment/versions.txt`: exact versions and artifact hashes.
- `poc/experiments/enrollment/mldsa-tls-negotiation.json`: measured ML-DSA sessions.
- `poc/experiments/enrollment/rsa-tls-negotiation.json`: measured RSA control sessions.

The full final local evidence is `../experiments/service-result.HMNgt6`.
Its container exited 0 and was not OOM-killed. Raw evidence includes disposable
private keys and tokens. It is retained locally and is not committed or uploaded.
The tested jar is retained at `../artifacts/server/puppet-server-release-tested.jar`.

Additional regression results:

| Check | Result |
| --- | --- |
| JVM SSL library upstream Clojure suite | 30 tests; 290 assertions; no failures or errors |
| Server generated-key signing and issuer-encoding checks | 42 assertions passed |
| Native agent cryptographic checks | 44 assertions passed |
| Focused agent existing specs | 385 passed; one legacy 3DES failure |
| Focused Vault/Hiera specs | 12 passed |
| Native CA CLI combined specs | 67 passed |
| FIPS dependency compatibility | Java compilation and profile checks passed; FIPS execution untested |

The 3DES failure also occurs on pristine agent source with this packaged
OpenSSL. It is not introduced by the ML-DSA changes. Full upstream server and
Ruby CI have not been run.

A separate clean source build also passed. Local evidence is
`../experiments/source-build/output-reproduction.dG1uQH`. Its jar SHA-256 is
`0ccd5c91433e7fb5887bd0bf2ddc72b7c73ca86b9fc157f715976185cf51a305`.
Build metadata changes jar hashes between builds. The 87-check run used the
original jar identified above, not this second jar.

## Reproduce the result

Docker and Git are required. The build needs network access. Tests run in a
restricted container with loopback networking only. Use disposable test paths.
The following layout is required by the existing drivers:

```text
lab/
  openvox-server/
  openvox/
  jvm-ssl-utils/
  openvoxserver-ca/
  vault-hiera/
  experiments/
```

To reconstruct a new lab from the pushed server branch:

```sh
lab=/absolute/path/to/new-disposable-lab
mkdir -p "$lab"
git clone --branch poc/mldsa-44 \
  https://github.com/Enucatl/openvox-server.git "$lab/openvox-server"
server="$lab/openvox-server"
while IFS="$(printf '\t')" read -r name url revision; do
  git clone "$url" "$lab/$name"
  git -C "$lab/$name" checkout --detach "$revision"
  cp -R "$server/poc/vendor/$name/." "$lab/$name/"
done < "$server/poc/dependencies.tsv"
cp -R "$server/poc/experiments" "$lab/experiments"
```

In an already assembled lab, use the current sibling checkouts instead. Do not
copy vendor overlays over unrelated work. The vendored directories contain only
changed files. They are not complete dependency checkouts.

From the lab directory:

1. Run `sh experiments/source-build/build-source.sh`. It installs the actual
   sibling SSL library, cleans and builds the server, checks dependency profiles,
   and tests providers and issuer-principal signing from the compiled artifact.
2. The driver prints a new `output-reproduction.*` directory. Copy that run's
   `puppet-server-release.jar` to
   `experiments/source-build/output/puppet-server-release.jar`. Create the
   `output` directory if needed. Use the exact printed directory, not a wildcard
   that can select several runs. Preserve the previous tested artifact separately.
3. Run `docker build -t openvox-vault-mldsa-poc:local experiments/vault`.
4. Run `sh experiments/run-service.sh enrollment`.
5. Check the new result directory. Require 87 PASS lines, no FAIL lines,
   `container-state.json` with exit code 0 and no OOM kill, and both TLS JSON files.
   Inspect the exact negotiated group as well as the signature assertions.

The final service runs as the package's `puppet` user. It has no external runtime
network, published ports, host mounts or Linux capabilities. It uses
`no-new-privileges`, 2 GB memory and two CPUs. Drivers record the actual container
exit status, copy evidence on failure, and remove their own container/image.
The source builder uses read-only source mounts and stages writable copies inside
the container. Dependency installation occurs in build containers.

The base-image digest, OpenVox package versions, BC checksums and Vault checksum
are pinned by the fixtures. Some Ubuntu packages and build downloads remain
repository-resolved. Record versions on every rebuild. These scripts do not
establish a fully hermetic release build.

In this Codex workspace, main-thread noninteractive commands expected to take
more than 30 seconds use the installed `wake-run` skill:

```sh
python3 /home/user/.agents/skills/wake-run/scripts/wake_run.py \
  --command 'sh /absolute/path/to/finalized-command-script.sh'
```

Read its installed `SKILL.md` first. When it reports `armed`, end the turn and
wait for the completion notification. Do not poll logs. Outside Codex, the same
build and test commands can run normally.

## Next engineering work

The core feasibility tests are complete. Focus on supported delivery:

1. Review the small implementation changes in each owning repository. Replace
   vendored snapshots with dependency branches and coordinated releases.
2. Build installable packages and run full upstream CI. Check supported OS,
   Ruby/OpenSSL and Java combinations. Keep RSA regression controls.
3. Decide the supported opt-in setup interface. The PoC prepares ML-DSA server
   keys before import. Avoid changing RSA defaults without a separate decision.
4. Review Java algorithm-policy compatibility. BCJSSE warns that it does not
   understand some JDK disabledAlgorithms clauses. The tests did not remove
   these clauses. Verify that the required policy is enforced.
5. Test malformed and already-expired CRLs, existing connections after revocation,
   and resumed TLS sessions. Fresh connection rejection and automatic CRL refresh
   already pass.
6. If required, measure Java-to-Vault handshakes and define a policy that requires
   hybrid key exchange for all relevant clients.

FIPS execution is optional unless the target deployment requires it. FIPS 204
defines ML-DSA. FIPS 140-3 concerns cryptographic module validation. Using the
algorithm does not validate the provider or deployment. The ordinary BCJSSE PoC
is not evidence for the separate FIPS runtime configuration.

Migration of an existing RSA fleet is a separate deployment test. Check mixed
trust, staged key replacement and rollback if that deployment needs them.
Vault storage, snapshots, seal access and root-key recovery are Vault operations.
They are not additional ML-DSA implementation blockers in OpenVox. OpenVox CA
backup/restore remains normal operational validation. No ML-DSA-specific recovery
mechanism has been shown to be necessary.

FreeIPA, NSS and Kerberos PKINIT are outside this PoC. A shared root does not
establish compatibility with these systems.

## ASD-STE100-inspired English guide

Use this guide for code comments, commit messages, reports and future handoffs.
It is inspired by ASD-STE100. Do not claim formal compliance.

- Use short sentences and common words. Put one main idea in each sentence.
- Use active voice. State the actor and the action.
- Use one technical term for one meaning. Keep exact identifiers unchanged.
- State the observed result before the implementation detail.
- Give the tested version and configuration when they affect the result.
- Separate observations, conclusions and work that remains untested.
- Use “passed” only when the named check passed. A negative test must reach
  the intended rejection, not fail at an earlier unrelated step.
- Distinguish a certificate signature, TLS handshake signature, key-exchange
  group and traffic cipher. Do not call all four “encryption”.
- State a real limitation once. Do not add generic warnings or speculative work.
- Keep Vault operations separate from OpenVox implementation requirements.

A technical report should contain the result, versions, method, positive and
negative checks, owning code or dependency, and remaining work. State whether
artifacts are available remotely or only on the local host. Never include private
keys, tokens or raw private runtime directories in a report or commit.

Original discussion: [control-repository issue 23](https://github.com/Enucatl/puppet-control-repo/issues/23).
Older reports describe earlier stages and may contain resolved blockers.
Publish further reports only when requested. This handoff and the final
credential-free results are the current implementation record.
