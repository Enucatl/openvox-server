FROM ubuntu:26.04@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl openjdk-25-jdk-headless openssl && curl -fsSLo /tmp/openvox-release.deb https://apt.voxpupuli.org/openvox9-release-ubuntu26.04.deb && dpkg -i /tmp/openvox-release.deb && apt-get update && apt-get install -y --no-install-recommends openvox-agent=9.1.0-1+ubuntu26.04 openvox-server=9.1.0-1+ubuntu26.04 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSLo /tmp/vault.zip https://releases.hashicorp.com/vault/2.2.0/vault_2.2.0_linux_amd64.zip && echo '05d78b0ac842ca7c522fc297df91527cd43c15420c4c5c0a969d48a7b0ff7b6d  /tmp/vault.zip' | sha256sum -c - && cd /usr/local/bin && jar xf /tmp/vault.zip vault && chmod 755 vault && rm /tmp/vault.zip
WORKDIR /test
COPY . /test/
RUN mkdir /private && chown -R puppet:puppet /private /test
USER puppet
ENTRYPOINT ["/bin/bash", "/test/run.sh"]
