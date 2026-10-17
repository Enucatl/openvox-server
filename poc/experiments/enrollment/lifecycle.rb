require 'openssl'
require 'net/http'
require 'json'
require 'fileutils'
require 'timeout'
require_relative 'vault-integration'

puts [RUBY_DESCRIPTION, OpenSSL::VERSION, OpenSSL::OPENSSL_LIBRARY_VERSION]
RESULTS = []

def check(name, value)
  RESULTS << [name, !!value]
  File.write('results.txt', RESULTS.map { |label, passed| "#{label}: #{passed ? 'PASS' : 'FAIL'}" }.join("\n") + "\n")
  raise "FAILED: #{name}" unless value
end

def http(method, path, identity: nil, body: nil)
  connection = Net::HTTP.new('localhost', 8140, nil)
  connection.use_ssl = true
  connection.ca_file = 'active/ca-chain.pem'
  connection.verify_mode = OpenSSL::SSL::VERIFY_PEER
  connection.verify_hostname = true
  connection.open_timeout = 5
  connection.read_timeout = 30
  if identity
    key_path, cert_path = identity
    connection.key = OpenSSL::PKey.read(File.read(key_path))
    connection.cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
    connection.extra_chain_cert = [OpenSSL::X509::Certificate.new(File.read('active/sub.pem'))]
  end
  request = Net::HTTP.const_get(method).new(path)
  request['Accept'] = 'application/json'
  request.body = body if body
  request['Content-Type'] = 'application/json' if body
  connection.start { |client| client.request(request) }
end

def agent_identity(name)
  ["active/#{name}/ssl/private_keys/#{name}.pem", "active/#{name}/ssl/certs/#{name}.pem"]
end

def run_agent(name, key_type, log, wait: 1)
  base = "/test/active/#{name}"
  FileUtils.mkdir_p("#{base}/ssl/certs")
  FileUtils.cp('active/ca-chain.pem', "#{base}/ssl/certs/ca.pem")
  command = ['/opt/puppetlabs/puppet/bin/ruby', '-r/test/tls-evidence.rb', '/opt/puppetlabs/puppet/bin/puppet', 'agent', '--test', '--confdir', base, '--vardir', "#{base}/var", '--publicdir', "#{base}/public", '--ssldir', "#{base}/ssl", '--rundir', "#{base}/run", '--logdir', "#{base}/log", '--certname', name, '--server', 'localhost', '--ca_server', 'localhost', '--key_type', key_type, '--waitforcert', wait.to_s, '--no-report', '--detailed-exitcodes', '--color', 'false']
  File.write("#{log}.command.json", JSON.pretty_generate(command))
  trace = { 'MLDSA_TLS_EVIDENCE' => "/test/#{log}.tls.jsonl" }
  pid = Process.spawn(trace, *command, out: log, err: [:child, :out])
  begin
    Timeout.timeout(180) { Process.wait(pid) }
    $?.exitstatus
  rescue Timeout::Error
    Process.kill('KILL', pid)
    Process.wait(pid)
    raise "Agent timed out; see #{log}"
  end
end

def cert_check(label, certificate, algorithm)
  issuer = OpenSSL::X509::Certificate.new(File.read('active/sub.pem'))
  check("#{label}/issuer_signature", certificate.verify(issuer.public_key))
  usage = certificate.extensions.find { |extension| extension.oid == 'keyUsage' }
  if algorithm == 'ML-DSA-44'
    oid = OpenSSL::ASN1.decode(certificate.public_key.public_to_der).value.first.value.first.oid
    check("#{label}/mldsa_public_key_and_signature", oid == '2.16.840.1.101.3.4.3.17' && certificate.signature_algorithm == 'ML-DSA-44')
    check("#{label}/signature_only_usage", usage.critical? && usage.value == 'Digital Signature')
  else
    check("#{label}/rsa_public_key_and_signature", certificate.public_key.is_a?(OpenSSL::PKey::RSA) && certificate.signature_algorithm == 'sha256WithRSAEncryption')
    check("#{label}/rsa_usage", usage.value.include?('Key Encipherment'))
  end
end

check('vault/exact_agent_role', configure_enrolled_agent_role.first == 204)
[['RSA', 'rsa'], ['ML-DSA-44', 'mldsa44']].each do |algorithm, key_type|
  label = "#{algorithm}-lifecycle"
  FileUtils.mkdir_p(label)
  environment = '/etc/puppetlabs/code/environments/production'
  if algorithm == 'ML-DSA-44'
    FileUtils.cp('/test/hiera.yaml', "#{environment}/hiera.yaml")
    File.write("#{environment}/manifests/site.pp", "file { '/test/applied-client': ensure => file, content => lookup('poc::marker') }\n")
  else
    FileUtils.rm_f("#{environment}/hiera.yaml")
  end
  FileUtils.rm_rf('active')
  FileUtils.mkdir_p('active')
  %w[server.pem server.key sub.pem].each { |name| FileUtils.cp("#{algorithm}/#{name}", "active/#{name}") }
  chain = File.read("#{algorithm}/sub.pem") + File.read("#{algorithm}/root.pem")
  File.write('active/import-chain.pem', chain)
  File.write('active/server.pub', OpenSSL::PKey.read(File.read('active/server.key')).public_to_pem)
  # Subordinate CRL comes first, matching OpenVox's imported-CA format.
  crls = File.read("#{algorithm}/sub.crl") + File.read("#{algorithm}/root.crl")
  File.write('active/import-crls.pem', crls)
  import_command = ['/opt/puppetlabs/bin/puppetserver', 'ca', 'import', '--config', '/etc/puppetlabs/puppet/puppet.conf', '--private-key', "#{algorithm}/sub.key", '--cert-bundle', 'active/import-chain.pem', '--crl-chain', 'active/import-crls.pem', '--subject-alt-names', 'localhost']
  File.write("#{label}/import-command.json", JSON.pretty_generate(import_command))
  check("#{label}/native_CA_import", system(*import_command, out: "#{label}/import.log", err: [:child, :out]))
  imported_server = OpenSSL::X509::Certificate.new(File.read('active/server-chain.pem'))
  cert_check("#{label}/imported_server", imported_server, algorithm)
  server_key = OpenSSL::PKey.read(File.read('active/server.key'))
  ca_key = OpenSSL::PKey.read(File.read('active/ca/ca_key.pem'))
  sub = OpenSSL::X509::Certificate.new(File.read('active/sub.pem'))
  check("#{label}/imported_key_pairs_match", server_key.public_to_der == imported_server.public_key.public_to_der && server_key.public_to_der == OpenSSL::PKey.read(File.read('active/server.pub')).public_to_der && ca_key.public_to_der == sub.public_key.public_to_der)
  File.write('active/server-chain.pem', imported_server.to_pem + chain)
  FileUtils.rm_f('/test/applied-client')
  options = ['-Xms256m', '-Xmx1024m', '-Dclojure.main.report=stderr', '--add-opens=java.base/sun.nio.ch=ALL-UNNAMED', '--add-opens=java.base/java.io=ALL-UNNAMED', '--enable-native-access=ALL-UNNAMED']
  if algorithm == 'ML-DSA-44'
    options << '-Djava.security.properties=/test/java.security.mldsa'
    schemes = 'mldsa44,rsa_pss_rsae_sha256,rsa_pss_pss_sha256,ecdsa_secp256r1_sha256,ed25519,rsa_pkcs1_sha256'
    %w[jdk.tls.client.SignatureSchemes jdk.tls.server.SignatureSchemes org.bouncycastle.jsse.client.SignatureSchemesCert org.bouncycastle.jsse.server.SignatureSchemesCert].each { |key| options << "-D#{key}=#{schemes}" }
  end
  provider = algorithm == 'ML-DSA-44' ? 'bc' : 'default'
  raise 'Source artifact startup provider probe failed' unless system('java', *options, '-cp', '.:server.jar', 'StartupProbe', provider, out: "#{label}/startup.log", err: [:child, :out])
  command = ['java', *options, '-cp', 'server.jar', 'clojure.main', '-m', 'puppetlabs.trapperkeeper.main', '--config', '/etc/puppetlabs/puppetserver/conf.d', '--bootstrap-config', '/etc/puppetlabs/puppetserver/services.d/,/opt/puppetlabs/server/apps/puppetserver/config/services.d/']
  File.write("#{label}/server-command.json", JSON.pretty_generate(command))
  pid = Process.spawn(*command, out: "#{label}/service.log", err: [:child, :out])
  begin
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 180
    loop do
      raise 'Server exited during startup' if Process.waitpid(pid, Process::WNOHANG)
      begin
        response = http('Get', '/puppet-ca/v1/certificate/ca')
        check("#{label}/authenticated_bootstrap_CA", response.code == '200' && response.body.include?(File.read("#{algorithm}/sub.pem").strip))
        break
      rescue Errno::ECONNREFUSED, EOFError, OpenSSL::SSL::SSLError
        raise 'Server readiness timed out' if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
        sleep 1
      end
    end
    application = algorithm == 'ML-DSA-44' ? 'fresh_agent_catalog_and_Hiera_apply' : 'fresh_agent_catalog_apply'
    check("#{label}/#{application}", run_agent('client', key_type, "#{label}/agent-first.log") == 2 && File.read('/test/applied-client') == 'mldsa-catalog-applied')
    original = OpenSSL::X509::Certificate.new(File.read(agent_identity('client').last))
    cert_check("#{label}/issued", original, algorithm)
    initial_crl = OpenSSL::X509::CRL.new(http('Get', '/puppet-ca/v1/certificate_revocation_list/ca').body)
    check("#{label}/automatic_CRL_expiry_refresh", initial_crl.next_update > Time.now + 30 * 86400 && initial_crl.extensions.find { |extension| extension.oid == 'crlNumber' }.value.to_i.positive? && initial_crl.verify(OpenSSL::X509::Certificate.new(File.read('active/sub.pem')).public_key))
    if algorithm == 'ML-DSA-44'
      status, login = vault_agent_login(agent_identity('client'), "#{label}/vault-enrolled")
      check("#{label}/Vault_auth_with_enrolled_identity", status == 200 && login.dig('auth', 'client_token') && login.dig('auth', 'policies').include?('poc'))
      token = login.fetch('auth').fetch('client_token')
      status, issued = vault_issue_with_agent_token(token, 'service.client.test', "#{label}/vault-issued")
      check("#{label}/Vault_authorized_issuance", status == 200)
      service_cert = OpenSSL::X509::Certificate.new(issued.fetch('data').fetch('certificate'))
      service_key = OpenSSL::PKey.read(issued.fetch('data').fetch('private_key'))
      root = OpenSSL::X509::Certificate.new(File.read('/test/vault-state/root.pem'))
      service_oid = OpenSSL::ASN1.decode(service_cert.public_key.public_to_der).value.first.value.first.oid
      check("#{label}/Vault_issued_key_and_certificate_MLDSA44", service_oid == '2.16.840.1.101.3.4.3.17' && service_cert.signature_algorithm == 'ML-DSA-44' && service_cert.verify(root.public_key) && service_key.public_to_der == service_cert.public_key.public_to_der)
      status, denied = vault_issue_with_agent_token(token, 'forbidden.example', "#{label}/vault-denied-domain")
      check("#{label}/Vault_issuance_denies_other_domain", status == 400 && denied.fetch('errors').any? { |error| error.include?('not allowed') })
      status, denied = vault_issue_with_agent_token(token, 'service.client.test', "#{label}/vault-denied-role", 'other-role')
      check("#{label}/Vault_issuance_denies_other_role", status == 403 && denied.fetch('errors').any? { |error| error.include?('permission denied') })
    end
    check("#{label}/subsequent_agent_converges", run_agent('client', key_type, "#{label}/agent-second.log") == 0)
    handshakes = File.readlines("#{label}/agent-second.log.tls.jsonl").map { |line| JSON.parse(line) }
    File.write("#{label}/tls-negotiation.json", JSON.pretty_generate(handshakes) + "\n")
    check("#{label}/actual_agent_TLS13_group_recorded", !handshakes.empty? && handshakes.all? { |tls| tls['hostname'] == 'localhost' && tls['port'] == 8140 && tls['protocol'] == 'TLSv1.3' && tls['group'].is_a?(String) && !tls['group'].empty? && tls['resumed'] == false })
    signature = algorithm == 'ML-DSA-44' ? /mldsa44/i : /rsa/i
    check("#{label}/actual_agent_both_TLS_signatures", handshakes.all? { |tls| %w[client_signature server_signature].all? { |side| tls[side].is_a?(String) && tls[side].delete('-_').match?(signature) } })
    check("#{label}/second_agent_enrolls", [0, 2].include?(run_agent('good', key_type, "#{label}/agent-good.log")))
    check("#{label}/unauthorized_name_not_enrolled", run_agent('denied', key_type, "#{label}/agent-denied.log", wait: 0) == 1 && File.exist?('active/ca/requests/denied.pem') && !File.exist?('active/ca/signed/denied.pem'))
    denied_csr = File.read('active/ca/requests/denied.pem')
    mismatch = http('Put', '/puppet-ca/v1/certificate_request/impostor', body: denied_csr)
    check("#{label}/CSR_name_mismatch_rejected", mismatch.code == '400' && !File.exist?('active/ca/signed/impostor.pem'))
    renewal = http('Post', '/puppet-ca/v1/certificate_renewal', identity: agent_identity('client'))
    check("#{label}/renewal_API", renewal.code == '200')
    renewed = OpenSSL::X509::Certificate.new(renewal.body)
    cert_check("#{label}/renewed", renewed, algorithm)
    check("#{label}/renewal_same_key_new_serial", renewed.public_key.public_to_der == original.public_key.public_to_der && renewed.serial != original.serial)
    File.write(agent_identity('client').last, renewed.to_pem)
    check("#{label}/renewed_identity_connects", http('Get', '/puppet/v3/environments', identity: agent_identity('client')).code == '200')
    if algorithm == 'ML-DSA-44'
      status, login = vault_agent_login(agent_identity('client'), "#{label}/vault-renewed")
      check("#{label}/Vault_auth_with_renewed_identity", status == 200 && login.dig('auth', 'client_token'))
    end
    unauthorized_admin = http('Put', '/puppet-ca/v1/certificate_status/good', identity: agent_identity('client'), body: JSON.generate(desired_state: 'revoked'))
    check("#{label}/agent_cannot_administer_CA", unauthorized_admin.code == '403')
    admin = ['active/server.key', 'active/server-chain.pem']
    revoke = http('Put', '/puppet-ca/v1/certificate_status/client', identity: admin, body: JSON.generate(desired_state: 'revoked'))
    check("#{label}/revoke_API", revoke.code == '204')
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 20
    loop do
      begin
        http('Get', '/puppet/v3/environments', identity: agent_identity('client'))
      rescue OpenSSL::SSL::SSLError => error
        raise unless error.message.match?(/certificate|revoked/i)
        File.write("#{label}/revocation-error.txt", error.message)
        break
      end
      raise 'Automatic CRL reload did not reject revoked identity' if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.2
    end
    check("#{label}/automatic_CRL_reload_rejects_revoked", true)
    check("#{label}/unrevoked_agent_still_connects", http('Get', '/puppet/v3/environments', identity: agent_identity('good')).code == '200')
    published = http('Get', '/puppet-ca/v1/certificate_revocation_list/ca')
    check("#{label}/CRL_published", published.code == '200')
    crl = OpenSSL::X509::CRL.new(published.body)
    issuer = OpenSSL::X509::Certificate.new(File.read('active/sub.pem'))
    check("#{label}/CRL_signature_and_both_serials_revoked", crl.verify(issuer.public_key) && [original.serial, renewed.serial].all? { |serial| crl.revoked.any? { |revoked| revoked.serial == serial } })
    check("#{label}/CRL_algorithm", crl.signature_algorithm == (algorithm == 'ML-DSA-44' ? 'ML-DSA-44' : 'sha256WithRSAEncryption'))
    if algorithm == 'ML-DSA-44'
      check("#{label}/Vault_CRL_publication", vault_publish_crl(crl).first == 204)
      status, login = vault_agent_login(agent_identity('client'), "#{label}/vault-revoked")
      check("#{label}/Vault_rejects_revoked_identity", status == 400 && login.fetch('errors').any? { |error| error.match?(/constraints|revoked/i) })
      status, login = vault_agent_login(agent_identity('good'), "#{label}/vault-good")
      check("#{label}/Vault_accepts_unrevoked_identity", status == 200 && login.dig('auth', 'client_token'))
    end
    FileUtils.mkdir_p("#{label}/revoked-identity")
    revoked_identity = ["#{label}/revoked-identity/client.key", "#{label}/revoked-identity/client.pem"]
    agent_identity('client').zip(revoked_identity).each { |source, target| FileUtils.cp(source, target) }
    cleanup = http('Delete', '/puppet-ca/v1/certificate_status/client', identity: admin)
    check("#{label}/authorized_identity_cleanup", cleanup.code == '204')
    FileUtils.rm_rf('active/client/ssl')
    check("#{label}/replacement_agent_applies", [0, 2].include?(run_agent('client', key_type, "#{label}/agent-replacement.log")))
    replacement = OpenSSL::X509::Certificate.new(File.read(agent_identity('client').last))
    cert_check("#{label}/replacement", replacement, algorithm)
    check("#{label}/replacement_has_new_key_and_serial", replacement.public_key.public_to_der != original.public_key.public_to_der && replacement.serial != renewed.serial)
    begin
      http('Get', '/puppet/v3/environments', identity: revoked_identity)
      raise 'The replaced revoked identity was accepted'
    rescue OpenSSL::SSL::SSLError => error
      check("#{label}/old_identity_stays_revoked", error.message.match?(/certificate|revoked/i))
    end
    if algorithm == 'ML-DSA-44'
      status, login = vault_agent_login(agent_identity('client'), "#{label}/vault-replacement")
      check("#{label}/Vault_accepts_replacement_identity", status == 200 && login.dig('auth', 'client_token'))
      status, login = vault_agent_login(revoked_identity, "#{label}/vault-old-identity")
      check("#{label}/Vault_old_identity_stays_revoked", status == 400 && login.fetch('errors').any? { |error| error.match?(/constraints|revoked/i) })
    end
  ensure
    FileUtils.cp_r('active', "#{label}/state")
    begin
      Process.kill('TERM', pid)
      Timeout.timeout(20) { Process.wait(pid) }
    rescue Timeout::Error
      Process.kill('KILL', pid)
      Process.wait(pid)
    rescue Errno::ESRCH, Errno::ECHILD
    end
  end
end
check('both_lifecycles_complete', RESULTS.size == 86)
