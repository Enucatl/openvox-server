FROM ubuntu:26.04@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl openjdk-25-jdk-headless && rm -rf /var/lib/apt/lists/*
WORKDIR /test
RUN mkdir bc && for artifact in bcprov bcpkix bcutil; do curl -fsSLo "bc/${artifact}-jdk18on-1.86.jar" "https://repo.maven.apache.org/maven2/org/bouncycastle/${artifact}-jdk18on/1.86/${artifact}-jdk18on-1.86.jar"; done
RUN printf '%s\n' '2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f  bc/bcprov-jdk18on-1.86.jar' '8d8b41a4b149bdae8d331f059a578870954d1e3ff29f8269a9eb3ee19a7e4ef7  bc/bcpkix-jdk18on-1.86.jar' '1c268e15f785aafb1e4670d8d6e5f856f69475e96c162dadcd1ff9b350e9139f  bc/bcutil-jdk18on-1.86.jar' | sha256sum -c -
COPY src/java src/java
COPY src/clojure src/clojure
COPY test/java test/java
RUN mkdir classes test-classes && javac --release 17 -cp 'bc/*' -d classes src/java/com/puppetlabs/ssl_utils/*.java && javac -cp 'classes:bc/*' -d test-classes test/java/com/puppetlabs/ssl_utils/IssuerSigningTest.java
RUN jar cf ssl-utils-3.7.2-SNAPSHOT-mldsa.jar -C classes com -C src/clojure puppetlabs
CMD ["java", "-ea", "-cp", "test-classes:classes:bc/*", "com.puppetlabs.ssl_utils.IssuerSigningTest"]
