require 'openssl'
require 'securerandom'
require 'active_support/time'

# Conjur certificate authority, for issuing X509 certificates for Conjur
# machines (eg. followers, standbys, etc.).
#
module Authentication
  module AuthnK8s
    class CA

      # Generate a CA key and certificate.
      #
      def self.cert_and_key(subject)
        key = OpenSSL::PKey::RSA.new(2048)

        cert = Util::OpenSsl::X509::Certificate.from_hash(
          subject: subject,
          issuer: subject,
          public_key: key.public_key,
          good_for: 10.years,
          extensions: [
            ['basicConstraints','CA:TRUE', true],
            ['subjectKeyIdentifier', 'hash'],
            ['authorityKeyIdentifier', 'keyid:always,issuer:always']
          ]
        )
        cert.sign(key, OpenSSL::Digest::SHA256.new)

        [ cert, key ]
      end

      def initialize(ca_cert, ca_key)
        raise "WTF"
        @ca_cert = ca_cert
        @ca_key = ca_key
      end

      # Issue a new certificate signed by CA's key
      #
      # Returns an OpenSSL::X509::Certificate
      #
      def signed_cert(csr, subject_altnames: nil, good_for: 3.days)
        Util::OpenSsl::X509::Certificate.from_hash(
          subject: csr.subject,
          issuer: @ca_cert.subject,
          public_key: csr.public_key,
          good_for: good_for,
          extensions: extensions(subject_altnames)
        ).tap do |cert|
          cert.sign(@ca_key, OpenSSL::Digest::SHA256.new)
        end
      end

      def verify(cert)
        cert.verify(@ca_key)
      end

      private

      def extensions(altnames)
        [
          ['keyUsage', 'digitalSignature,keyEncipherment', true],
          ['subjectKeyIdentifier', 'hash', false]
        ] +
        altnames ? [['subjectAltName', altnames.join(','), false]] : []
      end
    end
  end
end
