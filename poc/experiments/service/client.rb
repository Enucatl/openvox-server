require 'openssl'
require 'socket'
require 'timeout'
require 'fileutils'
require 'json'

puts [RUBY_DESCRIPTION, OpenSSL::VERSION, OpenSSL::OPENSSL_LIBRARY_VERSION]
SCHEMES = 'mldsa44,rsa_pss_rsae_sha256,rsa_pss_pss_sha256,ecdsa_secp256r1_sha256,ed25519,rsa_pkcs1_sha256'
PACKAGE_JAR = '/opt/puppetlabs/server/apps/puppetserver/puppet-server-release.jar'

def request(dir, scenario, path: '/puppet/v3/environments', expected: 'production')
  context = OpenSSL::SSL::SSLContext.new
  context.min_version = context.max_version = OpenSSL::SSL::TLS1_3_VERSION
  context.verify_mode = OpenSSL::SSL::VERIFY_PEER
  context.verify_hostname = true
  context.ca_file = "#{dir}/#{scenario == 'untrusted_server' ? 'other' : 'root'}.pem"
  unless scenario == 'missing_client'
    identity = scenario == 'untrusted_client' ? 'rogue' : 'client'
    context.cert = OpenSSL::X509::Certificate.new(File.read("#{dir}/#{identity}.pem"))
    context.key = OpenSSL::PKey.read(File.read("#{dir}/#{identity}.key"))
    context.extra_chain_cert = [OpenSSL::X509::Certificate.new(File.read("#{dir}/sub.pem"))] unless identity == 'rogue'
  end
  Timeout.timeout(30) do
    Socket.tcp('127.0.0.1', 8140, connect_timeout: 3) do |tcp|
      ssl = OpenSSL::SSL::SSLSocket.new(tcp, context)
      ssl.hostname = scenario == 'wrong_hostname' ? 'wrong.example' : 'localhost'
      begin
        ssl.connect
        ssl.post_connection_check(ssl.hostname)
        raise 'verification failed' unless ssl.verify_result == OpenSSL::X509::V_OK
        if dir == 'ML-DSA-44'
          ssl.peer_cert_chain.each do |certificate|
            oid = OpenSSL::ASN1.decode(certificate.public_key.public_to_der).value.first.value.first.oid
            raise 'unexpected peer algorithm' unless oid == '2.16.840.1.101.3.4.3.17' && certificate.signature_algorithm == 'ML-DSA-44'
          end
        end
        ssl.write("GET #{path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n")
        response = ssl.read
        raise "unexpected response #{response.inspect}" unless response.start_with?('HTTP/1.1 200') && response.include?(expected)
        puts "ACCEPTED #{ssl.ssl_version} #{ssl.cipher.first} #{response.lines.first.strip}"
        response
      ensure
        ssl.close
      end
    end
  end
end

def outbound_listener(dir, label)
  context = OpenSSL::SSL::SSLContext.new
  context.min_version = context.max_version = OpenSSL::SSL::TLS1_3_VERSION
  context.cert = OpenSSL::X509::Certificate.new(File.read("#{dir}/server.pem"))
  context.key = OpenSSL::PKey.read(File.read("#{dir}/server.key"))
  context.extra_chain_cert = [OpenSSL::X509::Certificate.new(File.read("#{dir}/sub.pem"))]
  context.ca_file = "#{dir}/root.pem"
  context.verify_mode = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
  tcp = TCPServer.new('127.0.0.1', 9443)
  listener = OpenSSL::SSL::SSLServer.new(tcp, context)
  records = []
  worker = Thread.new do
    loop do
      begin
        ssl = listener.accept
        Timeout.timeout(10) do
          line = ssl.gets
          next unless line
          raise "Unexpected Java request: #{line}" unless line.start_with?('GET / HTTP/1.1')
          raise 'Java client certificate was not verified' unless ssl.verify_result == OpenSSL::X509::V_OK
          raise 'Wrong Java client identity' unless ssl.peer_cert.subject.to_a.any? { |name, value, _| name == 'CN' && value == 'server' }
          record = {protocol: ssl.ssl_version, cipher: ssl.cipher.first, subject: ssl.peer_cert.subject.to_s, signature: ssl.peer_cert.signature_algorithm}
          if dir == 'ML-DSA-44'
            oid = OpenSSL::ASN1.decode(ssl.peer_cert.public_key.public_to_der).value.first.value.first.oid
            raise 'Java peer is not ML-DSA-44' unless oid == '2.16.840.1.101.3.4.3.17' && record[:signature] == 'ML-DSA-44'
          end
          records << record
          File.write("#{label}/outbound.json", JSON.pretty_generate(records))
          body = "outbound-https-ok\n"
          ssl.write("HTTP/1.1 200 OK\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
        end
      rescue OpenSSL::SSL::SSLError => error
        File.open("#{label}/outbound-tls.log", 'a') { |file| file.puts(error.message) }
      ensure
        ssl&.close
      end
    end
  end
  [tcp, worker, records]
end

results = []
[['RSA', 'default'], ['RSA', 'bc'], ['ML-DSA-44', 'bc']].each do |dir, provider|
  label = "#{dir}-#{provider}"
  FileUtils.mkdir_p(label)
  %w[server.pem server.key root.pem clean.crl].each { |name| FileUtils.cp("#{dir}/#{name}", "active/#{name}") }
  File.write('active/server-chain.pem', File.read("#{dir}/server.pem") + File.read("#{dir}/sub.pem"))
  classpath = provider == 'bc' ? "bc/*:#{PACKAGE_JAR}" : PACKAGE_JAR
  options = ['-Xms256m', '-Xmx1024m', '-Dclojure.main.report=stderr', '--add-opens=java.base/sun.nio.ch=ALL-UNNAMED', '--add-opens=java.base/java.io=ALL-UNNAMED', '--enable-native-access=ALL-UNNAMED']
  if provider == 'bc'
    options << '-Djava.security.properties=/test/java.security.mldsa'
    %w[jdk.tls.client.SignatureSchemes jdk.tls.server.SignatureSchemes org.bouncycastle.jsse.client.SignatureSchemesCert org.bouncycastle.jsse.server.SignatureSchemesCert].each do |key|
      options << "-D#{key}=#{SCHEMES}"
    end
  end
  raise "#{label} startup probe failed" unless system('java', *options, '-cp', ".:#{classpath}", 'StartupProbe', provider, out: "#{label}/startup.log", err: [:child, :out])
  command = ['java', *options, '-cp', classpath, 'clojure.main', '-m', 'puppetlabs.trapperkeeper.main', '--config', '/etc/puppetlabs/puppetserver/conf.d', '--bootstrap-config', '/etc/puppetlabs/puppetserver/services.d/,/opt/puppetlabs/server/apps/puppetserver/config/services.d/']
  File.write("#{label}/command.json", JSON.pretty_generate(command))
  pid = Process.spawn(*command, out: "#{label}/service.log", err: [:child, :out])
  listener, worker, outbound_records = outbound_listener(dir, label)
  begin
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 180
    loop do
      raise "#{label} service exited during startup" if Process.waitpid(pid, Process::WNOHANG)
      begin
        response = request(dir, 'valid')
        File.write("#{label}/environments.http", response)
        results << ["#{label}/valid", true]
        break
      rescue Errno::ECONNREFUSED, OpenSSL::SSL::SSLError, EOFError, Timeout::Error => error
        raise "#{label} readiness timeout: #{error.class}: #{error.message}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
        sleep 1
      end
    end
    response = request(dir, 'valid', path: '/puppet/v3/catalog/client?environment=production', expected: 'outbound-https-ok')
    File.write("#{label}/catalog.http", response)
    FileUtils.cp('active/outbound-hostname-rejection.txt', "#{label}/outbound-hostname-rejection.txt")
    worker.value unless worker.alive?
    raise 'Both outbound Java trust contexts must make a verified request' unless outbound_records.size == 2
    results << ["#{label}/catalog_and_outbound_https", true]
    %w[missing_client untrusted_server untrusted_client wrong_hostname].each do |scenario|
      passed = false
      begin
        request(dir, scenario)
        puts "#{label}/#{scenario}: unexpectedly accepted"
      rescue OpenSSL::SSL::SSLError => error
        # Only certificate/hostname failures count; connection/setup errors fail the case.
        pattern = scenario == 'wrong_hostname' ? /hostname|certificate verify failed/i : /certificate|unknown ca|bad certificate/i
        passed = error.message.match?(pattern)
        puts "#{label}/#{scenario}: #{error.class}: #{error.message}"
      end
      results << ["#{label}/#{scenario}", passed]
    end
  ensure
    worker.kill
    worker.join
    listener.close
    begin
      Process.kill('TERM', pid)
      begin
        Timeout.timeout(20) { Process.wait(pid) }
      rescue Timeout::Error
        Process.kill('KILL', pid)
        Process.wait(pid)
      end
    rescue Errno::ESRCH, Errno::ECHILD
    end
    File.write('results.txt', results.map { |name, pass| "#{name}: #{pass ? 'PASS' : 'FAIL'}" }.join("\n") + "\n")
  end
end
raise 'full-service baseline failed' unless results.size == 18 && results.all?(&:last)
