# frozen_string_literal: true
require 'openssl'
require 'socket'
require 'net/http'
require 'json'
require 'securerandom'
require 'fileutils'

DIR = ENV.fetch('VAULT_POC_DIR', '/private')
FileUtils.mkdir_p(DIR, mode: 0o700)
File.umask(0o077)

def assert(value, message)
  raise message unless value
  puts "PASS #{message}"
end

def key
  OpenSSL::PKey.generate_key('ML-DSA-44')
end

def request_for(private_key, name)
  request = OpenSSL::X509::Request.new
  request.version = 0
  request.subject = OpenSSL::X509::Name.new([['CN', name]])
  request.public_key = private_key
  request.sign(private_key, nil)
  raise 'CSR verification failed' unless request.verify(request.public_key)
  request
end

def certificate(private_key, name, issuer = nil, issuer_key = private_key, ca: false)
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = SecureRandom.random_number(2**128)
  cert.subject = OpenSSL::X509::Name.new([['CN', name]])
  cert.issuer = issuer ? issuer.subject : cert.subject
  cert.public_key = private_key
  cert.not_before = Time.now - 60
  cert.not_after = Time.now + 3600
  factory = OpenSSL::X509::ExtensionFactory.new
  factory.subject_certificate = cert
  factory.issuer_certificate = issuer || cert
  cert.add_extension(factory.create_extension('basicConstraints', ca ? 'CA:TRUE,pathlen:0' : 'CA:FALSE', true))
  cert.add_extension(factory.create_extension('keyUsage', ca ? 'keyCertSign,cRLSign' : 'digitalSignature', true))
  unless ca
    cert.add_extension(factory.create_extension('extendedKeyUsage', 'serverAuth,clientAuth'))
    cert.add_extension(factory.create_extension('subjectAltName', "DNS:#{name}"))
  end
  cert.add_extension(factory.create_extension('subjectKeyIdentifier', 'hash'))
  cert.add_extension(factory.create_extension('authorityKeyIdentifier', 'keyid:always')) if issuer
  cert.sign(issuer_key, nil)
  cert
end

def write(name, content)
  File.write("#{DIR}/#{name}", content)
end

def api(path, body = nil, token: File.read("#{DIR}/root-token"))
  uri = URI("http://127.0.0.1:8200/v1/#{path}")
  request = body ? Net::HTTP::Post.new(uri) : Net::HTTP::Get.new(uri)
  request['X-Vault-Token'] = token
  request['Content-Type'] = 'application/json'
  request.body = JSON.generate(body) if body
  response = Net::HTTP.start(uri.hostname, uri.port, nil) { |http| http.request(request) }
  parsed = response.body.to_s.empty? ? {} : JSON.parse(response.body)
  write("#{path.tr('/', '-')}.json", JSON.pretty_generate(parsed))
  raise "Vault #{path} HTTP #{response.code}: #{parsed['errors']}" unless response.is_a?(Net::HTTPSuccess)
  parsed['data']
end

def login(name, cert = nil, private_key = nil, chain = [])
  context = OpenSSL::SSL::SSLContext.new
  context.min_version = OpenSSL::SSL::TLS1_3_VERSION
  context.ca_file = "#{DIR}/root.pem"
  context.verify_mode = OpenSSL::SSL::VERIFY_PEER
  context.cert = cert if cert
  context.key = private_key if private_key
  context.extra_chain_cert = chain
  tcp = TCPSocket.new('127.0.0.1', 8202)
  socket = OpenSSL::SSL::SSLSocket.new(tcp, context)
  socket.sync_close = true
  socket.hostname = 'localhost'
  socket.connect
  socket.post_connection_check('localhost')
  body = JSON.generate(name: name)
  socket.write("POST /v1/auth/cert/login HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
  raw = socket.read
  status = raw.lines.first.split[1].to_i
  payload = JSON.parse(raw.split("\r\n\r\n", 2).last)
  write("login-#{name}-#{cert ? cert.serial : 'missing'}.json", JSON.pretty_generate(payload))
  puts "TLS #{socket.ssl_version} #{socket.cipher[0]}; peer public-key OID #{OpenSSL::ASN1.decode(socket.peer_cert.public_key.public_to_der).value[0].value[0].oid} signature #{socket.peer_cert.signature_algorithm}; HTTP #{status}"
  [status, payload]
ensure
  socket&.close
end

puts `vault version`
puts "Ruby #{RUBY_VERSION}; Ruby OpenSSL #{OpenSSL::VERSION}; #{OpenSSL::OPENSSL_LIBRARY_VERSION}"
write('versions.txt', `vault version` + "Ruby #{RUBY_VERSION}; Ruby OpenSSL #{OpenSSL::VERSION}; #{OpenSSL::OPENSSL_LIBRARY_VERSION}\n")
write('root-token', SecureRandom.hex(32))
transport_key = key
write('server.key', transport_key.private_to_pem)
# Go accepts the RFC 9881 seed-only encoding, not OpenSSL's combined encoding.
raise 'Seed-only conversion failed' unless system('/opt/puppetlabs/puppet/bin/openssl', 'pkey', '-in', "#{DIR}/server.key", '-provparam', 'ml-dsa.output_formats=seed-only', '-out', "#{DIR}/server-seed.key")
File.rename("#{DIR}/server-seed.key", "#{DIR}/server.key")
write('server.pem', certificate(transport_key, 'localhost').to_pem)
write('vault.hcl', <<~HCL)
  disable_mlock = true
  listener "tcp" {
    address = "127.0.0.1:8202"
    tls_cert_file = "#{DIR}/server.pem"
    tls_key_file = "#{DIR}/server.key"
    tls_min_version = "tls13"
    tls_reload_interval = "1s"
  }
HCL
pid = Process.spawn('vault', 'server', '-dev', "-dev-root-token-id=#{File.read("#{DIR}/root-token")}", '-dev-listen-address=127.0.0.1:8200', "-config=#{DIR}/vault.hcl", out: "#{DIR}/vault.log", err: [:child, :out])
write('vault.pid', pid.to_s)
completed = false
begin
  ready = false
  100.times do
    begin
      Net::HTTP.start('127.0.0.1', 8200, nil) { |http| ready = http.get('/v1/sys/health').code == '200' }
    rescue Errno::ECONNREFUSED
      # Vault initializes in the isolated container before accepting requests.
    end
    break if ready
    raise 'Vault exited during startup; inspect private vault.log' if Process.waitpid(pid, Process::WNOHANG)
    sleep 0.1
  end
  raise 'Vault startup timed out' unless ready
  api('sys/mounts/pki', { type: 'pki', config: { max_lease_ttl: '24h' } })
  root_data = api('pki/root/generate/internal', { common_name: 'Vault ML-DSA-44 Root', key_type: 'ml-dsa', parameter_set: 'ml-dsa-44', ttl: '24h', max_path_length: 1 })
  write('root.pem', root_data.fetch('certificate'))
  root = OpenSSL::X509::Certificate.new(root_data.fetch('certificate'))
  api('pki/crl/rotate')
  root_crl_response = Net::HTTP.start('127.0.0.1', 8200, nil) { |http| http.get('/v1/pki/crl/pem') }
  raise 'Vault root CRL download failed' unless root_crl_response.is_a?(Net::HTTPSuccess)
  root_crl = OpenSSL::X509::CRL.new(root_crl_response.body)
  write('root-crl.pem', root_crl.to_pem)
  assert(root_crl.signature_algorithm == 'ML-DSA-44' && root_crl.verify(root.public_key), 'Vault root CRL uses verified ML-DSA-44 signature')
  sub_key = key
  sub_csr = request_for(sub_key, 'OpenVox ML-DSA-44 CA')
  write('sub.key', sub_key.private_to_pem)
  write('sub.csr', sub_csr.to_pem)
  sub_data = api('pki/root/sign-intermediate', { csr: sub_csr.to_pem, common_name: 'OpenVox ML-DSA-44 CA', ttl: '12h', max_path_length: 0, use_csr_values: true })
  sub = OpenSSL::X509::Certificate.new(sub_data.fetch('certificate'))
  write('sub.pem', sub.to_pem)
  write('ca-chain.pem', sub.to_pem + root.to_pem)
  sub_crl = OpenSSL::X509::CRL.new
  sub_crl.version = 1
  sub_crl.issuer = sub.subject
  sub_crl.last_update = Time.now - 60
  sub_crl.next_update = Time.now + 3600
  sub_crl.add_extension(OpenSSL::X509::Extension.new('crlNumber', OpenSSL::ASN1::Integer.new(0).to_der))
  crl_extensions = OpenSSL::X509::ExtensionFactory.new
  crl_extensions.issuer_certificate = sub
  sub_crl.add_extension(crl_extensions.create_extension('authorityKeyIdentifier', 'keyid:always'))
  sub_crl.sign(sub_key, nil)
  write('sub-crl.pem', sub_crl.to_pem)
  write('crl-chain.pem', sub_crl.to_pem + root_crl.to_pem)
  assert(sub.verify(root.public_key), 'Vault signed external ML-DSA-44 subordinate CSR')
  assert(sub.extensions.any? { |e| e.oid == 'basicConstraints' && e.value == 'CA:TRUE, pathlen:0' && e.critical? }, 'Subordinate has critical CA:TRUE,pathlen:0')
  assert(sub.extensions.any? { |e| e.oid == 'keyUsage' && e.value.include?('Certificate Sign') && e.value.include?('CRL Sign') }, 'Subordinate permits certificate and CRL signing')
  server = certificate(transport_key, 'localhost', sub, sub_key)
  write('server.pem', server.to_pem + sub.to_pem)
  sleep 1.5
  client_key = key
  client = certificate(client_key, 'agent.test', sub, sub_key)
  write('client.key', client_key.private_to_pem)
  write('client.pem', client.to_pem)
  write('client-chain.pem', client.to_pem + sub.to_pem)
  [root, sub, server, client].each do |cert|
    assert(OpenSSL::ASN1.decode(cert.public_key.public_to_der).value[0].value[0].oid == '2.16.840.1.101.3.4.3.17' && cert.signature_algorithm == 'ML-DSA-44', "ML-DSA-44 key and signature: #{cert.subject}")
  end
  api('sys/auth/cert', { type: 'cert' })
  api('sys/policies/acl/poc', { policy: 'path "auth/token/lookup-self" { capabilities = ["read"] }' })
  api('auth/cert/certs/openvox', { certificate: sub.to_pem, allowed_common_names: 'agent.test', allowed_dns_sans: 'agent.test', token_policies: 'poc', token_ttl: '15m' })
  status, payload = login('openvox', client, client_key, [sub])
  assert(status == 200 && payload.dig('auth', 'client_token') && payload.dig('auth', 'policies').include?('poc'), 'Vault certificate auth accepts authorized ML-DSA-44 agent')
  rogue_key = key
  rogue_sub = certificate(rogue_key, 'OpenVox ML-DSA-44 CA', ca: true)
  rogue_client = certificate(client_key, 'agent.test', rogue_sub, rogue_key)
  status, payload = login('openvox', rogue_client, client_key, [rogue_sub])
  assert(status == 400 && payload.fetch('errors').any? { |e| e.include?('invalid') || e.include?('failed') || e.include?('certificate') }, 'Vault certificate auth rejects same-name wrong issuer')
  wrong_name = certificate(client_key, 'other.test', sub, sub_key)
  status, payload = login('openvox', wrong_name, client_key, [sub])
  assert(status == 400 && payload.fetch('errors').any?, 'Vault certificate auth rejects unauthorized name under correct issuer')
  status, payload = login('openvox')
  assert(status == 400 && payload.fetch('errors').any? { |e| e.include?('certificate') }, 'Vault certificate auth rejects missing client certificate')
  completed = true
  puts 'PASS Vault hierarchy and cert-auth PoC complete'
ensure
  unless completed && ENV['KEEP_VAULT'] == 'true'
    Process.kill('TERM', pid) rescue Errno::ESRCH
    Process.wait(pid) rescue Errno::ECHILD
  end
end
