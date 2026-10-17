require 'puppet/server/http_client'
require 'uri'

Puppet::Functions.create_function(:mldsa_probe) do
  def mldsa_probe
    client = Puppet::Server::HttpClient.new
    [false, true].each do |system_store|
      response = client.get(URI('https://localhost:9443/'), options: {include_system_store: system_store})
      raise "Outbound HTTPS failed: #{response.code}" unless response.code == 200 && response.body == "outbound-https-ok\n"
    end
    begin
      client.get(URI('https://127.0.0.1:9443/'))
    rescue Puppet::Server::HttpClientError => error
      cause = error.cause
      cause = cause.getCause while cause.respond_to?(:getCause) && cause.getCause
      raise unless cause && cause.java_class.name == 'javax.net.ssl.SSLPeerUnverifiedException' && cause.message.match?(/does not match/i)
      File.write('/test/active/outbound-hostname-rejection.txt', "#{cause.java_class.name}: #{cause.message}\n")
      return 'outbound-https-ok'
    end
    raise 'Outbound HTTPS accepted the wrong hostname'
  end
end
