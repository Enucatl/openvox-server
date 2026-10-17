# frozen_string_literal: true
require 'openssl'
require 'net/http'
require 'json'
require 'fileutils'

# Administrative traffic stays on the disposable container's loopback listener.
def vault_admin_write(path, body)
  connection = Net::HTTP.new('127.0.0.1', 8200, nil)
  connection.open_timeout = 5
  connection.read_timeout = 30
  request = Net::HTTP::Post.new("/v1/#{path}")
  request['X-Vault-Token'] = File.read('/test/vault-state/root-token')
  request['Content-Type'] = 'application/json'
  request.body = JSON.generate(body)
  response = connection.start { |client| client.request(request) }
  parsed = response.body.to_s.empty? ? {} : JSON.parse(response.body)
  raise "Vault #{path} returned HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

  [response.code.to_i, parsed]
end

def configure_enrolled_agent_role
  vault_admin_write('sys/mounts/kv', { type: 'kv', options: { version: '2' } })
  vault_admin_write('kv/data/puppet', { data: { 'poc::marker' => 'mldsa-catalog-applied' } })
  vault_admin_write('sys/policies/acl/puppet-server', {
    policy: 'path "kv/data/puppet" { capabilities = ["read"] }'
  })
  vault_admin_write('auth/cert/certs/puppet-server', {
    certificate: File.read('/test/vault-state/sub.pem'),
    allowed_common_names: ['server'],
    allowed_dns_sans: ['localhost'],
    token_policies: ['puppet-server'],
    token_no_default_policy: true,
    token_ttl: '15m'
  })
  vault_admin_write('pki/roles/poc-service', {
    key_type: 'ml-dsa', parameter_set: 'ml-dsa-44',
    allowed_domains: ['service.client.test'], allow_bare_domains: true,
    allow_subdomains: false, allow_wildcard_certificates: false,
    allow_glob_domains: false, allow_any_name: false,
    allow_localhost: false, allow_ip_sans: false,
    ttl: '15m', max_ttl: '30m', key_usage: ['DigitalSignature'],
    server_flag: true, client_flag: false
  })
  vault_admin_write('sys/policies/acl/poc', {
    policy: 'path "auth/token/lookup-self" { capabilities = ["read"] }
             path "pki/issue/poc-service" { capabilities = ["update"] }'
  })
  vault_admin_write('auth/cert/certs/openvox', {
    certificate: File.read('/test/vault-state/sub.pem'),
    allowed_common_names: ['client', 'good'],
    allowed_dns_sans: ['client', 'good'],
    token_policies: ['poc'],
    token_no_default_policy: true,
    token_ttl: '15m'
  })
end

def vault_tls_connection
  connection = Net::HTTP.new('localhost', 8202, nil)
  connection.use_ssl = true
  connection.ca_file = '/test/vault-state/root.pem'
  connection.verify_mode = OpenSSL::SSL::VERIFY_PEER
  connection.verify_hostname = true
  connection.min_version = OpenSSL::SSL::TLS1_3_VERSION
  connection.open_timeout = 5
  connection.read_timeout = 30
  connection
end

def vault_private_response(response, label, filename)
  parsed = JSON.parse(response.body)
  FileUtils.mkdir_p(label, mode: 0o700)
  File.open(File.join(label, filename), 'w', 0o600) { |file| file.write(JSON.pretty_generate(parsed)) }
  [response.code.to_i, parsed]
end

# Return [HTTP status, parsed JSON]; keep issued tokens in private test evidence.
def vault_agent_login(identity, label)
  key_path, cert_path = identity
  connection = vault_tls_connection
  connection.key = OpenSSL::PKey.read(File.read(key_path))
  connection.cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
  connection.extra_chain_cert = [OpenSSL::X509::Certificate.new(File.read('/test/vault-state/sub.pem'))]
  request = Net::HTTP::Post.new('/v1/auth/cert/login')
  request['Content-Type'] = 'application/json'
  request.body = JSON.generate(name: 'openvox')
  response = connection.start { |client| client.request(request) }
  vault_private_response(response, label, 'vault-login.json')
end

# This blocks new certificate logins; already issued Vault tokens retain their TTL.
def vault_publish_crl(crl)
  issuer = OpenSSL::X509::Certificate.new(File.read('/test/vault-state/sub.pem'))
  raise 'CRL is not signed by the OpenVox subordinate' unless crl.issuer.to_der == issuer.subject.to_der && crl.verify(issuer.public_key)

  vault_admin_write('auth/cert/crls/openvox', { crl: crl.to_pem })
end

# Issue only through the authenticated agent's scoped policy, keeping keys private.
def vault_issue_with_agent_token(token, common_name, label, role = 'poc-service')
  connection = vault_tls_connection
  request = Net::HTTP::Post.new("/v1/pki/issue/#{role}")
  request['X-Vault-Token'] = token
  request['Content-Type'] = 'application/json'
  request.body = JSON.generate(common_name: common_name, ttl: '15m')
  response = connection.start { |client| client.request(request) }
  vault_private_response(response, label, 'vault-issue.json')
end
