FROM ubuntu:26.04@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl openjdk-25-jdk-headless openssl && curl -fsSLo /tmp/openvox-release.deb https://apt.voxpupuli.org/openvox9-release-ubuntu26.04.deb && dpkg -i /tmp/openvox-release.deb && apt-get update && apt-get install -y --no-install-recommends openvox-agent=9.1.0-1+ubuntu26.04 openvox-server=9.1.0-1+ubuntu26.04 && rm -rf /var/lib/apt/lists/*
WORKDIR /test
RUN mkdir bc && for artifact in bcprov bcpkix bcutil; do curl -fsSLo "bc/${artifact}-jdk18on-1.86.jar" "https://repo.maven.apache.org/maven2/org/bouncycastle/${artifact}-jdk18on/1.86/${artifact}-jdk18on-1.86.jar"; done && curl -fsSLo bc/bctls-jdk18on-1.86.2.jar https://repo.maven.apache.org/maven2/org/bouncycastle/bctls-jdk18on/1.86.2/bctls-jdk18on-1.86.2.jar
RUN printf '%s\n' '2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f  bc/bcprov-jdk18on-1.86.jar' '8d8b41a4b149bdae8d331f059a578870954d1e3ff29f8269a9eb3ee19a7e4ef7  bc/bcpkix-jdk18on-1.86.jar' '1c268e15f785aafb1e4670d8d6e5f856f69475e96c162dadcd1ff9b350e9139f  bc/bcutil-jdk18on-1.86.jar' '8ce8d5fb1b5d323a73df1fdba920b2f97c12d047986028fe65bf64d3997e50f2  bc/bctls-jdk18on-1.86.2.jar' | sha256sum -c -
COPY run.sh client.rb outbound.rb StartupProbe.java generate.sh rogue.sh crls.sh java.security.mldsa /test/
RUN javac StartupProbe.java
RUN mkdir -p /test/active /etc/puppetlabs/code/environments/production/manifests /var/run/puppetlabs/puppetserver && chown -R puppet:puppet /test /etc/puppetlabs/puppet /etc/puppetlabs/puppetserver /etc/puppetlabs/code /var/run/puppetlabs/puppetserver /var/log/puppetlabs/puppetserver /opt/puppetlabs/server/data/puppetserver
USER puppet
