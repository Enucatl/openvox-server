#!/bin/sh
set -eu
for algorithm in RSA ML-DSA-44; do
  mkdir -p "$algorithm"
  cd "$algorithm"
  for identity in root sub server client other; do
    openssl genpkey -algorithm "$algorithm" -out "$identity.key" 2>/dev/null
  done
  openssl req -new -x509 -key root.key -out root.pem -subj /CN=TestRoot -days 2 -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' -addext 'keyUsage=critical,keyCertSign,cRLSign'
  openssl req -new -x509 -key other.key -out other.pem -subj /CN=OtherRoot -days 2 -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
  cat > sub.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
  openssl req -new -key sub.key -out sub.csr -subj /CN=TestSub
  openssl x509 -req -in sub.csr -CA root.pem -CAkey root.key -set_serial 2 -out sub.pem -days 2 -extfile sub.ext
  for identity in server client; do
    cat > "$identity.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=${identity}Auth
subjectAltName=DNS:localhost
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
    openssl req -new -key "$identity.key" -out "$identity.csr" -subj "/CN=$identity"
    openssl x509 -req -in "$identity.csr" -CA sub.pem -CAkey sub.key -set_serial "$(if [ "$identity" = server ]; then echo 3; else echo 4; fi)" -out "$identity.pem" -days 2 -extfile "$identity.ext"
    openssl verify -CAfile root.pem -untrusted sub.pem -purpose "$(if [ "$identity" = server ]; then echo sslserver; else echo sslclient; fi)" "$identity.pem"
  done
  openssl pkcs8 -topk8 -nocrypt -in server.key -outform DER -out server.der
  for identity in root sub server client; do
    openssl x509 -in "$identity.pem" -noout -text | sed -n '/Signature Algorithm:/p;/Public Key Algorithm:/p'
  done
  cd ..
done
