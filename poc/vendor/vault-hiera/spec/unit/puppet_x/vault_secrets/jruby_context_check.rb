# Run with the OpenVox Server classpath and a generated ML-DSA identity directory.
require 'puppet/server/http_client'
require_relative '../../../../lib/puppet_x/vault_secrets/vaultsession'

Puppet.initialize_settings
Puppet[:hostcert] = File.join(ARGV.fetch(0), 'cert.pem')
Puppet[:hostprivkey] = File.join(ARGV.fetch(0), 'key.pem')

session = VaultSession.new('uri' => 'https://localhost:8200/v1/kv/data/puppet',
                           'token' => 'test-token', 'ca_trust' => Puppet[:hostcert], 'timeout' => 7)
session.configure_java_http(Puppet[:hostcert], 7, false)
options = session.instance_variable_get(:@java_options)
raise 'wrong connect timeout' unless options.get_connect_timeout_milliseconds == 7000
raise 'wrong read timeout' unless options.get_socket_timeout_milliseconds == 7000
raise 'redirects enabled' if options.get_follow_redirects
context = options.get_ssl_context
raise 'wrong TLS provider' unless context.provider.name == 'BCJSSE'
puts "ML-DSA context: #{context.provider}, #{context.create_ssl_engine.java_class.name}"
puts 'JRUBY_MLDSA_CONTEXT_PASS'
