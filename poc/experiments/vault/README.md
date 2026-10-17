Vault ML-DSA-44 PoC
===================

The public Vault 2.2.0 binary generates an internal ML-DSA-44 root and signs an
external ML-DSA-44 subordinate CSR. Bundled OpenVox Ruby generates the subordinate,
server and client keys. The script verifies CA constraints, certificate signatures,
Vault's root CRL, TLS server trust/hostname and actual certificate authentication.
Wrong issuer, unauthorized name and missing client certificate return HTTP 400.

Build from this directory's Dockerfile. Run without host mounts or published ports:

```sh
docker build -t openvox-vault-mldsa-poc:local experiments/vault
docker create --name vault-mldsa-test --network none --cap-drop ALL \
  --security-opt no-new-privileges --memory 1g --cpus 2 \
  openvox-vault-mldsa-poc:local
docker start -a vault-mldsa-test
docker inspect --format '{{.State.ExitCode}}' vault-mldsa-test
```

Copy `/private/.` into a private directory before removing the container. It contains
private keys, bootstrap and issued tokens, and Vault logs; do not publish it.
`results.txt` contains the successful run's public output. The final tested image ID
was `sha256:8e13e75cff508eb7b5ab721163022f9a5700d6f83a869d2ba26d2a6af71455bc`.

For a combined OpenVox test, copy `setup.sh` and `vault-poc.rb` together and run
`VAULT_POC_DIR=/test/vault-state bash /test/vault/setup.sh`. It leaves Vault running;
the caller must kill the PID in `vault-state/vault.pid` on exit. HTTP bootstrap is
loopback port 8200; TLS certificate authentication is port 8202, hostname `localhost`.
The cert-auth role is `auth/cert/certs/openvox`, with exact CN/SAN `agent.test` and
policy `poc` (token self-lookup only). Set its exact permitted names for the combined
test before login. Never grant the bootstrap token to the client.

Fixtures: `root.pem`, `sub.pem`, `sub.key`, `sub.csr`, `ca-chain.pem` (subordinate,
root), `server.pem` (localhost leaf, subordinate), `server.key`, `client.pem`,
`client.key`, `root-crl.pem`, `sub-crl.pem`, `crl-chain.pem` (subordinate CRL, root CRL).
Leaf certificates and the subordinate CRL expire after one hour. The internal root
key stays in Vault's ephemeral memory; this is not a recovery procedure.

Vault's Go loader requires ML-DSA seed-only private PEM. The script converts only
the Vault listener key with bundled OpenSSL 3.5.9. Ruby accepts the default combined
seed/expanded encoding. Use bundled Ruby for agent certificate authentication;
the Vault CLI also rejects combined private keys. Vault 2.2.0 dev-mode SIGHUP caused
a nil-pointer crash in an earlier run; automatic TLS certificate reload works.
TLS 1.3 and cipher are recorded; key exchange and handshake signature schemes
were not measured. No production service, credential or configuration was used.

Pinned archive SHA-256:
`05d78b0ac842ca7c522fc297df91527cd43c15420c4c5c0a969d48a7b0ff7b6d`.
Actual extracted `/usr/local/bin/vault` SHA-256:
`64884404557ee590b43a1842c9cd5a3777895213c34bc10eac05ceb550a4aae7`.

Sources: [Vault PKI API](https://developer.hashicorp.com/vault/api-docs/secret/pki),
[cert authentication](https://developer.hashicorp.com/vault/docs/auth/cert),
[TLS listener configuration](https://developer.hashicorp.com/vault/docs/configuration/listener/tcp),
[Vault 2.2.0 checksums](https://releases.hashicorp.com/vault/2.2.0/vault_2.2.0_SHA256SUMS).
