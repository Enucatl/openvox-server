FROM ubuntu:26.04@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944
ENV DEBIAN_FRONTEND=noninteractive LEIN_ROOT=1
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl openjdk-25-jdk-headless openssl && curl -fsSLo /tmp/openvox-release.deb https://apt.voxpupuli.org/openvox9-release-ubuntu26.04.deb && dpkg -i /tmp/openvox-release.deb && apt-get update && apt-get install -y --no-install-recommends openvox-agent=9.1.0-1+ubuntu26.04 openvox-server=9.1.0-1+ubuntu26.04 && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y --no-install-recommends git unzip leiningen && rm -rf /var/lib/apt/lists/*
RUN curl -fsSLo /usr/local/bin/lein https://raw.githubusercontent.com/technomancy/leiningen/2.12.0/bin/lein && chmod 755 /usr/local/bin/lein && mkdir -p /root/.lein/self-installs && curl -fsSLo /root/.lein/self-installs/leiningen-2.12.0-standalone.jar https://github.com/technomancy/leiningen/releases/download/2.12.0/leiningen-2.12.0-standalone.jar
WORKDIR /build
