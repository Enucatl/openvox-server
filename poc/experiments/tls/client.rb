require 'openssl'
require 'socket'
require 'timeout'
require 'fileutils'

puts [RUBY_DESCRIPTION, OpenSSL::VERSION, OpenSSL::OPENSSL_LIBRARY_VERSION]
results = []
%w[RSA ML-DSA-44].each do |dir|
  FileUtils.rm_f(["#{dir}/ready", "#{dir}/reloaded"])
  input, control = IO.pipe
  pid = Process.spawn('java', '-cp', File.read('classpath').strip, 'JettyTest', dir, in: input, out: "#{dir}/jetty.log", err: [:child, :out])
  input.close
  begin
    Timeout.timeout(30) { sleep 0.05 until File.exist?("#{dir}/ready") }
    port = File.read("#{dir}/ready").to_i
    phases = {'clean' => %w[client good missing_client untrusted_server untrusted_client wrong_hostname], 'revoked' => %w[client good]}
    phases.each do |phase, cases|
      if phase == 'revoked'
        control.puts 'reload'; control.flush
        Timeout.timeout(15) { sleep 0.05 until File.exist?("#{dir}/reloaded") }
      end
      cases.each do |scenario|
        expected = scenario == 'good' || (scenario == 'client' && phase == 'clean')
        success = false
        begin
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION
          ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER; ctx.verify_hostname = true
          ctx.ca_file = "#{dir}/#{scenario == 'untrusted_server' ? 'other' : 'root'}.pem"
          unless scenario == 'missing_client'
            identity = scenario == 'untrusted_client' ? 'rogue' : (scenario == 'good' ? 'good' : 'client')
            ctx.cert = OpenSSL::X509::Certificate.new(File.read("#{dir}/#{identity}.pem"))
            ctx.key = OpenSSL::PKey.read(File.read("#{dir}/#{identity}.key"))
            ctx.extra_chain_cert = [OpenSSL::X509::Certificate.new(File.read("#{dir}/sub.pem"))] unless identity == 'rogue'
          end
          Timeout.timeout(8) do
            Socket.tcp('127.0.0.1', port, connect_timeout: 3) do |tcp|
              ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
              ssl.hostname = scenario == 'wrong_hostname' ? 'wrong.example' : 'localhost'
              ssl.connect; ssl.post_connection_check(ssl.hostname)
              raise 'verification failed' unless ssl.verify_result == OpenSSL::X509::V_OK
              ssl.peer_cert_chain.each do |cert|
                oid = OpenSSL::ASN1.decode(cert.public_key.public_to_der).value.first.value.first.oid
                if dir == 'ML-DSA-44'
                  raise 'unexpected peer algorithm' unless oid == '2.16.840.1.101.3.4.3.17' && cert.signature_algorithm == 'ML-DSA-44'
                end
              end
              ssl.write("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
              response = ssl.read
              raise "bad HTTP response: #{response.inspect}" unless response.start_with?('HTTP/1.1 200') && response.include?("pong\n")
              puts "#{dir}/#{phase}/#{scenario}: ACCEPTED #{ssl.ssl_version} #{ssl.cipher.first}"
              ssl.close; success = true
            end
          end
        rescue StandardError => e
          puts "#{dir}/#{phase}/#{scenario}: REJECTED #{e.class}: #{e.message}"
        end
        results << ["#{dir}/#{phase}/#{scenario}", success == expected]
      end
    end
    control.puts 'stop'; control.flush
    Timeout.timeout(10) { Process.wait(pid) }
    raise 'Jetty process failed' unless $?.success?
  ensure
    control.close
    begin
      Process.kill('TERM', pid); Process.wait(pid)
    rescue Errno::ESRCH, Errno::ECHILD
    end
  end
end
File.write('results.txt', results.map { |label, pass| "#{label}: #{pass ? 'PASS' : 'FAIL'}" }.join("\n") + "\n")
exit(results.all?(&:last) ? 0 : 1)
