#!/bin/sh
set -eu
cd /test
umask 077
trap 'if [ -f /test/vault-state/vault.pid ]; then kill "$(cat /test/vault-state/vault.pid)" || true; fi; cp -R /var/log/puppetlabs/puppetserver /test/package-logs' EXIT
echo 'Source-built OpenVox server9.1.1-SNAPSHOT and ssl-utils with patched agent library on package9.1.0 runtime.' > scope.txt
{ dpkg-query -W openvox-agent openvox-server openjdk-25-jre-headless; java -version; vault version; sha256sum server.jar /usr/local/bin/vault; } > versions.txt 2>&1
sh generate.sh > generate.log 2>&1
for algorithm in RSA ML-DSA-44; do
  sed -i 's/^extendedKeyUsage=serverAuth$/extendedKeyUsage=serverAuth,clientAuth/' "$algorithm/server.ext"
  openssl x509 -req -in "$algorithm/server.csr" -CA "$algorithm/sub.pem" -CAkey "$algorithm/sub.key" -set_serial 3 -out "$algorithm/server.pem" -days 2 -extfile "$algorithm/server.ext" >> generate.log 2>&1
done
sh crls.sh > crls.log 2>&1
VAULT_POC_DIR=/test/vault-state bash /test/vault/vault-setup.sh > vault-setup.log 2>&1
for name in root.pem sub.pem sub.key server.key; do cp "vault-state/$name" "ML-DSA-44/$name"; done
openssl x509 -in vault-state/server.pem -out ML-DSA-44/server.pem
cp vault-state/root-crl.pem ML-DSA-44/root.crl
cp vault-state/sub-crl.pem ML-DSA-44/sub.crl
rm ML-DSA-44/root.key
mkdir -p active /etc/puppetlabs/code/environments/production/manifests
printf "file { '/test/applied-client': ensure => file, content => 'mldsa-catalog-applied' }\n" > /etc/puppetlabs/code/environments/production/manifests/site.pp
cp auth.conf /etc/puppetlabs/puppetserver/conf.d/auth.conf
cat > /etc/puppetlabs/puppet/puppet.conf <<'EOF'
[main]
certname = server
ssldir = /test/active/ssl
hostcert = /test/active/server-chain.pem
hostprivkey = /test/active/server.key
hostpubkey = /test/active/server.pub
localcacert = /test/active/ca-chain.pem
hostcrl = /test/active/host.crl
cadir = /test/active/ca
autosign = /test/autosign.conf
codedir = /etc/puppetlabs/code
ca_ttl = 1h
EOF
printf 'client\ngood\n' > autosign.conf
cat > /etc/puppetlabs/puppetserver/conf.d/webserver.conf <<'EOF'
webserver: {
  ssl-host: "127.0.0.1"
  ssl-port: 8140
  client-auth: want
  ssl-cert: /test/active/server-chain.pem
  ssl-key: /test/active/server.key
  ssl-ca-cert: /test/active/ca-chain.pem
  ssl-crl-path: /test/active/host.crl
  ssl-protocols: [TLSv1.3]
}
EOF
cat >> /etc/puppetlabs/puppetserver/conf.d/puppetserver.conf <<'EOF'

jruby-puppet: { max-active-instances: 1 }
EOF
cat > /etc/puppetlabs/puppetserver/conf.d/ca.conf <<'EOF'
certificate-authority: {
  allow-auto-renewal: true
  auto-renewal-cert-ttl: "1h"
}
EOF
mkdir config-evidence
cp -R /etc/puppetlabs/puppetserver/conf.d /etc/puppetlabs/puppetserver/services.d config-evidence/
cp /etc/puppetlabs/puppet/puppet.conf config-evidence/
/opt/puppetlabs/puppet/bin/ruby lifecycle.rb > lifecycle.log 2>&1 || { code=$?; tail -80 lifecycle.log; exit "$code"; }
cat results.txt
