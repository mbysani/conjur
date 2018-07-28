# A declarative constructor for an X509::Certificate
#
# TODO: this could pulled out into a gem

require 'openssl'

module Util
  module OpenSsl
    module X509
      module Certificate
        def self.from_hash(
          subject:,
          issuer:,
          public_key:,
          good_for:, # accepts any object with to_i
          version: 2,
          serial: SecureRandom.random_number(2**160), # 20 bytes
          issuer_cert: nil, # if nil, assumed to be self
          extensions: [] # an array of arrays
        )
          now = Time.now

          cert = OpenSSL::X509::Certificate.new
          cert.subject = openssl_name(subject)
          cert.issuer = openssl_name(issuer)
          cert.not_before = now
          cert.not_after = now + good_for.to_i
          cert.public_key = public_key
          cert.serial = SecureRandom.random_number(2**160) # 20 bytes
          cert.version = 2

          ef = OpenSSL::X509::ExtensionFactory.new
          ef.subject_certificate = cert
          ef.issuer_certificate = issuer_cert || cert

          extensions.each do |args|
            cert.add_extension(ef.create_extension(*args))
          end

          cert
        end

        private

        def self.openssl_name(name)
          is_obj = name.is_a?(OpenSSL::X509::Name)
          is_obj ? name : OpenSSL::X509::Name.parse(name)
        end
      end
    end
  end
end
