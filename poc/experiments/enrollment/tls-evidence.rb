require 'openssl'
require 'json'

# Observe the real agent's completed handshakes without changing TLS settings.
module AgentTLSEvidence
  def connect(...)
    result = super
    record_tls_evidence if result.equal?(self)
    result
  end

  def connect_nonblock(...)
    result = super
    record_tls_evidence if result.equal?(self)
    result
  end

  private

  def record_tls_evidence
    return if @tls_evidence_recorded

    evidence = {
      hostname: hostname, port: to_io.peeraddr[1], protocol: ssl_version,
      cipher: cipher.first, group: group, client_signature: sigalg,
      server_signature: peer_sigalg, resumed: session_reused?,
      client_certificate: cert&.subject&.to_s,
      server_certificate: peer_cert.subject.to_s
    }
    File.open(ENV.fetch('MLDSA_TLS_EVIDENCE'), 'a', 0o600) { |file| file.puts(JSON.generate(evidence)) }
    @tls_evidence_recorded = true
  end
end

OpenSSL::SSL::SSLSocket.prepend(AgentTLSEvidence)
