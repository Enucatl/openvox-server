#!/bin/sh
set -eu
cd /test
umask 077
trap 'cp -R /var/log/puppetlabs/puppetserver /test/package-logs' EXIT
echo 'PACKAGED OPENVOX 9.1.0 BASELINE; cloned source changes are not built into this image.' > scope.txt
{ dpkg-query -W openvox-agent openvox-server openjdk-25-jre-headless; java -version; openssl version; sha256sum bc/*.jar; } > versions.txt 2>&1
sh generate.sh > generate.log 2>&1
# OpenVox's server identity also authenticates outbound HTTPS requests.
for algorithm in RSA ML-DSA-44; do
  sed -i 's/^extendedKeyUsage=serverAuth$/extendedKeyUsage=serverAuth,clientAuth/' "$algorithm/server.ext"
  openssl x509 -req -in "$algorithm/server.csr" -CA "$algorithm/sub.pem" -CAkey "$algorithm/sub.key" -set_serial 3 -out "$algorithm/server.pem" -days 2 -extfile "$algorithm/server.ext" >> generate.log 2>&1
done
sh rogue.sh > rogue.log 2>&1
sh crls.sh > crls.log 2>&1
mkdir -p active /etc/puppetlabs/code/environments/production/manifests /etc/puppetlabs/code/environments/production/modules/mldsa_probe/lib/puppet/functions /var/run/puppetlabs/puppetserver
cp outbound.rb /etc/puppetlabs/code/environments/production/modules/mldsa_probe/lib/puppet/functions/mldsa_probe.rb
printf 'notify { mldsa_probe(): }\n' > /etc/puppetlabs/code/environments/production/manifests/site.pp
cat > /etc/puppetlabs/puppet/puppet.conf <<'EOF'
[main]
certname = server
ssldir = /test/active/ssl
hostcert = /test/active/server-chain.pem
hostprivkey = /test/active/server.key
localcacert = /test/active/root.pem
hostcrl = /test/active/clean.crl
codedir = /etc/puppetlabs/code
environment = production
EOF
cat > /etc/puppetlabs/puppetserver/conf.d/webserver.conf <<'EOF'
webserver: {
  ssl-host: "127.0.0.1"
  ssl-port: 8140
  client-auth: need
  ssl-cert: /test/active/server-chain.pem
  ssl-key: /test/active/server.key
  ssl-ca-cert: /test/active/root.pem
  ssl-crl-path: /test/active/clean.crl
  ssl-protocols: [TLSv1.3]
}
EOF
cat >> /etc/puppetlabs/puppetserver/conf.d/puppetserver.conf <<'EOF'

jruby-puppet: { max-active-instances: 1 }
EOF
cat > /etc/puppetlabs/puppetserver/conf.d/auth.conf <<'EOF'
authorization: {
  version: 1
  rules: [{
    match-request: {path: "/puppet/v3/environments", type: path, method: get}
    allow: "client"
    sort-order: 100
    name: "authenticated isolated environments test"
  }, {
    match-request: {path: "/puppet/v3/catalog/client", type: path, method: get}
    allow: "client"
    sort-order: 100
    name: "authenticated isolated catalog test"
  }, {
    match-request: {path: "/", type: path}
    deny: "*"
    sort-order: 999
    name: "deny everything else"
  }]
}
EOF
test -d /etc/puppetlabs/puppetserver/services.d
for config in /etc/puppetlabs/puppetserver/services.d/*.cfg; do
  sed -i 's@^[[:space:]]*puppetlabs.services.ca.certificate-authority-service/certificate-authority-service@# CA disabled for imported identity baseline@' "$config"
done
printf '%s\n' 'puppetlabs.services.ca.certificate-authority-disabled-service/certificate-authority-disabled-service' > /etc/puppetlabs/puppetserver/services.d/zz-test-ca-disabled.cfg
test -f /opt/puppetlabs/server/apps/puppetserver/puppet-server-release.jar
mkdir -p config-evidence
cp -R /etc/puppetlabs/puppetserver/conf.d /etc/puppetlabs/puppetserver/services.d config-evidence/
cp -R /opt/puppetlabs/server/apps/puppetserver/config/services.d config-evidence/core-services.d
cp /etc/puppetlabs/puppet/puppet.conf config-evidence/
cp /etc/default/puppetserver config-evidence/package-defaults
/opt/puppetlabs/puppet/bin/ruby client.rb > client.log 2>&1
