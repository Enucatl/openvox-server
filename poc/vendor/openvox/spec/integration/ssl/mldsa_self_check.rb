# frozen_string_literal: true

# Run with the packaged Ruby/OpenSSL 3.5+: ruby -Ilib spec/integration/ssl/mldsa_self_check.rb
require 'puppet'
require 'puppet/application/ssl'
require 'tmpdir'
require 'fileutils'

checks = 0
assert = lambda do |condition, message|
  raise message unless condition

  checks += 1
end
reject = lambda do |error, &block|
  begin
    block.call
  rescue error
    checks += 1
  else
    raise "Expected #{error}"
  end
end

puts "Ruby #{RUBY_VERSION}; Ruby OpenSSL #{OpenSSL::VERSION}; #{OpenSSL::OPENSSL_LIBRARY_VERSION}"
assert.call(Puppet[:key_type] == 'rsa', 'RSA must remain the default')
reject.call(Puppet::Settings::ValidationError) do
  Puppet[:key_type] = 'ML-DSA-65'
  Puppet[:key_type]
end
Puppet[:key_type] = 'rsa'

Dir.mktmpdir('openvox-mldsa') do |dir|
  Puppet.initialize_settings(['--confdir', dir, '--vardir', dir, '--ssldir', "#{dir}/ssl", '--certname', 'agent.test'])
  Puppet[:hostcert_renewal_interval] = 0
  FileUtils.mkdir_p([Puppet[:privatekeydir], Puppet[:certdir], Puppet[:requestdir]])
  cert_provider = Puppet::X509::CertProvider.new
  ssl_provider = Puppet::SSL::SSLProvider.new

  %w[rsa ec mldsa44].each do |algorithm|
    Puppet[:key_type] = algorithm
    Puppet[:keylength] = 2048
    FileUtils.rm_f(Puppet[:hostprivkey])
    machine = Puppet::SSL::StateMachine.new(cert_provider: cert_provider, ssl_provider: ssl_provider)
    context = Puppet::SSL::SSLContext.new(cacerts: [], crls: [])
    state = Puppet::SSL::StateMachine::NeedKey.new(machine, context).next_state
    key = state.private_key
    assert.call(state.is_a?(Puppet::SSL::StateMachine::NeedSubmitCSR), "#{algorithm}: CSR state")
    loaded = cert_provider.load_private_key(Puppet[:certname], required: true)
    assert.call(key.public_to_der == loaded.public_to_der, "#{algorithm}: persisted private key")
    assert.call((File.stat(Puppet[:hostprivkey]).mode & 0o777) == 0o640, "#{algorithm}: private key permissions")
    reused = Puppet::SSL::StateMachine::NeedKey.new(machine, context).next_state.private_key
    assert.call(key.public_to_der == reused.public_to_der, "#{algorithm}: existing key reused")

    csr = cert_provider.create_request(Puppet[:certname], loaded)
    assert.call(csr.verify(csr.public_key), "#{algorithm}: CSR signature")
    assert.call(csr.public_key.public_to_der == key.public_to_der, "#{algorithm}: CSR public key")
    ssl_provider.verify_request(csr, loaded)
    cert_provider.save_request(Puppet[:certname], csr)
    assert.call(OpenSSL::X509::Request.new(File.read(Puppet[:hostcsr])).verify(loaded), "#{algorithm}: saved CSR")

    cert_provider.save_private_key(Puppet[:certname], key, password: 'test-password')
    encrypted_key = cert_provider.load_private_key(Puppet[:certname], password: 'test-password', required: true)
    assert.call(encrypted_key.public_to_der == key.public_to_der, "#{algorithm}: encrypted private key")
    reject.call(OpenSSL::PKey::PKeyError) { cert_provider.load_private_key(Puppet[:certname], password: 'wrong-password') }

    cli_key = Puppet::Application::Ssl.allocate.send(:create_key, Puppet[:certname])
    assert.call(cli_key.public_to_der != key.public_to_der, "#{algorithm}: CLI generates a fresh key")
    assert.call(Puppet::SSL.mldsa44_key?(cli_key) == (algorithm == 'mldsa44'), "#{algorithm}: CLI key algorithm")

    next unless algorithm == 'mldsa44'

    assert.call(Puppet::SSL.mldsa44_key?(loaded), 'ML-DSA-44 public key OID')
    assert.call(csr.signature_algorithm == 'ML-DSA-44', 'ML-DSA-44 CSR signature algorithm')
    named_request = Puppet::SSL::CertificateRequest.new(Puppet[:certname])
    named_request.generate(key, dns_alt_names: 'alias.test', csr_attributes: { '1.2.3.4' => 'test' })
    assert.call(named_request.subject_alt_names == ['DNS:agent.test', 'DNS:alias.test'], 'ML-DSA SAN preservation')
    assert.call(named_request.custom_attributes == [{ 'oid' => '1.2.3.4', 'value' => 'test' }], 'ML-DSA CSR attribute preservation')

    root = OpenSSL::X509::Certificate.new
    root.version = 2
    root.serial = 1
    root.subject = OpenSSL::X509::Name.parse('/CN=ML-DSA test root')
    root.issuer = root.subject
    root.public_key = key
    root.not_before = Time.now - 60
    root.not_after = Time.now + 3600
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = root
    factory.issuer_certificate = root
    root.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
    root.add_extension(factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
    root.sign(key, nil)
    leaf_key = cli_key
    leaf = OpenSSL::X509::Certificate.new
    leaf.version = 2
    leaf.serial = 2
    leaf.subject = csr.subject
    leaf.issuer = root.subject
    leaf.public_key = leaf_key
    leaf.not_before = root.not_before
    leaf.not_after = root.not_after
    leaf.sign(key, nil)
    crl = OpenSSL::X509::CRL.new
    crl.version = 1
    crl.issuer = root.subject
    crl.last_update = Time.now - 60
    crl.next_update = Time.now + 3600
    crl.sign(key, nil)
    args = { cacerts: [root], crls: [crl], client_cert: leaf }
    verified = ssl_provider.create_context(**args, private_key: leaf_key)
    assert.call(verified.private_key == leaf_key, 'ML-DSA chain, CRL and matching private key accepted')
    reject.call(Puppet::SSL::SSLError) { ssl_provider.create_context(**args, private_key: key) }
    reject.call(Puppet::SSL::SSLError) { ssl_provider.create_context(**args, private_key: OpenSSL::PKey.generate_key('ML-DSA-65')) }
    rogue_root = root.dup
    rogue_root.public_key = leaf_key
    rogue_root.sign(leaf_key, nil)
    reject.call(Puppet::SSL::CertVerifyError) { ssl_provider.create_context(**args.merge(cacerts: [rogue_root]), private_key: leaf_key) }
    revoked = OpenSSL::X509::Revoked.new
    revoked.serial = leaf.serial
    revoked.time = Time.now - 30
    crl.add_revoked(revoked)
    crl.sign(key, nil)
    reject.call(Puppet::SSL::CertVerifyError) { ssl_provider.create_context(**args, private_key: leaf_key) }
  end
end
puts "PASS: #{checks} agent key, CSR, persistence, chain and rejection checks"
