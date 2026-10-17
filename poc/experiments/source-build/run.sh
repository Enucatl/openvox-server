#!/bin/sh
set -eu
mkdir -p /output /ssl-source /build
test -f /ssl-input/project.clj
tar -C /ssl-input --exclude=./.git --exclude=./target -cf - . | tar --no-same-owner -C /ssl-source -xf -
cd /ssl-source
timeout 300 lein clean > /output/ssl-utils-clean.log 2>&1
timeout 900 lein install > /output/ssl-utils-install.log 2>&1
cp target/ssl-utils-3.7.2-SNAPSHOT.jar /output/
sha256sum /output/ssl-utils-3.7.2-SNAPSHOT.jar > /output/ssl-utils-sha256.txt
tar -C /source --exclude=./handoff.md --exclude=./.git --exclude=./target -cf - . | tar --no-same-owner -C /build -xf -
cd /build
export PUPPETSERVER_HEAP_SIZE=1G
lein version > /output/versions.txt 2>&1
dpkg-query -W openvox-agent openvox-server openjdk-25-jre-headless >> /output/versions.txt
java -version >> /output/versions.txt 2>&1
java -cp /root/.lein/self-installs/leiningen-2.12.0-standalone.jar clojure.main /checks/check-profiles.clj > /output/profiles.log 2>&1
timeout 900 lein deps :tree > /output/dev-dependencies.log 2>&1
timeout 300 lein clean > /output/server-clean.log 2>&1
timeout 900 lein uberjar > /output/uberjar-build.log 2>&1
test -f target/puppet-server-release.jar
cp target/puppet-server-release.jar /output/
jar tf /output/puppet-server-release.jar > /output/uberjar-entries.txt
grep -q '^org/bouncycastle/jsse/provider/BouncyCastleJsseProvider.class$' /output/uberjar-entries.txt
sha256sum /output/puppet-server-release.jar > /output/sha256.txt
timeout 300 lein install > /output/local-install.log 2>&1
timeout 900 lein with-profile user,ezbake,provided deps :tree > /output/ezbake-dependencies.log 2>&1
grep -q 'org.bouncycastle/bctls-jdk18on "1.86.2"' /output/ezbake-dependencies.log
javac -d /output /checks/ArtifactProbe.java
java -Djava.security.properties=/build/resources/ext/java.security.mldsa -cp /output:/output/puppet-server-release.jar ArtifactProbe > /output/artifact-probe.log 2>&1
java -Djava.security.properties=/build/resources/ext/java.security.mldsa -cp /output/puppet-server-release.jar clojure.main /checks/signing-probe.clj > /output/artifact-signing-probe.log 2>&1
