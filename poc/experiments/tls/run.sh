#!/bin/sh
set -eu
cd /test
dpkg-query -W openvox-agent openvox-server openjdk-25-jre-headless > versions.txt
java -version >> versions.txt 2>&1
sh generate.sh > generation.log 2>&1
sh rogue.sh >> generation.log 2>&1
sh crls.sh > crls.log 2>&1
classpath=".:$(find /test/bc -name '*.jar' | paste -sd:):/opt/puppetlabs/server/apps/puppetserver/puppet-server-release.jar"
printf '%s\n' "$classpath" > classpath
javac -cp "$classpath" JettyTest.java EngineProbe.java
java -cp "$classpath" EngineProbe > engine-probe.log 2>&1
sha256sum /test/bc/*.jar >> versions.txt
set +e
/opt/puppetlabs/puppet/bin/ruby client.rb > client.log 2>&1
code=$?
cat versions.txt client.log
if [ -f results.txt ]; then cat results.txt; fi
exit "$code"
