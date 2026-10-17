#!/bin/sh
set -eu
for algorithm in RSA ML-DSA-44; do
  cd "$algorithm"
  openssl genpkey -algorithm "$algorithm" -out good.key 2>/dev/null
  openssl req -new -key good.key -out good.csr -subj /CN=GoodClient
  openssl x509 -req -in good.csr -CA sub.pem -CAkey sub.key -set_serial 6 -out good.pem -days 2 -extfile client.ext
  for ca in root sub; do
    mkdir -p "$ca-db/newcerts"
    : > "$ca-db/index"
    printf '1000\n' > "$ca-db/crlnumber"
    cat > "$ca.cnf" <<EOF
[ca]
default_ca=issuer
[issuer]
database=$ca-db/index
new_certs_dir=$ca-db/newcerts
certificate=$ca.pem
private_key=$ca.key
crlnumber=$ca-db/crlnumber
default_md=default
default_crl_days=1
policy=policy
crl_extensions=crl_ext
[policy]
commonName=supplied
[crl_ext]
authorityKeyIdentifier=keyid:always
EOF
    openssl ca -config "$ca.cnf" -gencrl -out "$ca.crl" -batch
  done
  cat root.crl sub.crl > clean.crl
  openssl verify -CAfile root.pem -untrusted sub.pem -CRLfile clean.crl -crl_check_all client.pem good.pem
  openssl ca -config sub.cnf -revoke client.pem -batch
  openssl ca -config sub.cnf -gencrl -out sub-revoked.crl -batch
  cat root.crl sub-revoked.crl > revoked.crl
  openssl verify -CAfile root.pem -untrusted sub.pem -CRLfile revoked.crl -crl_check_all good.pem
  if openssl verify -CAfile root.pem -untrusted sub.pem -CRLfile revoked.crl -crl_check_all client.pem > revoked-verify.txt 2>&1; then
    echo 'revoked certificate was accepted' >&2; exit 1
  fi
  grep 'certificate revoked' revoked-verify.txt
  openssl crl -in sub-revoked.crl -noout -text
  cp clean.crl active.crl
  cd ..
done
