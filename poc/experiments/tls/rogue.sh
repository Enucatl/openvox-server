#!/bin/sh
set -eu
for algorithm in RSA ML-DSA-44; do
  cd "$algorithm"
  openssl genpkey -algorithm "$algorithm" -out rogue.key 2>/dev/null
  openssl req -new -key rogue.key -out rogue.csr -subj /CN=RogueClient
  openssl x509 -req -in rogue.csr -CA other.pem -CAkey other.key -set_serial 5 -out rogue.pem -days 2 -extfile client.ext
  cd ..
done
