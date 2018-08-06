# Represents a Certificate Authority that can issue new signed certificates.
# It can also be thought of as a representation of a certificate and its
# associated key.
#
require 'openssl'
require 'securerandom'
require 'active_support/time'

module Util
  module OpenSsl
    class CA

      attr_reader :cert, :key

      # Generate a CA key and certificate.
      #
      def self.from_subject(subject)
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

        self.new(cert, key)
      end

      def initialize(cert, key)
        @cert = cert
        @key = key
      end

      # Issue a new certificate signed by CA's key
      #
      # Returns an OpenSSL::X509::Certificate
      #
      def signed_cert(csr, subject_altnames: nil, good_for: 3.days)
        Util::OpenSsl::X509::Certificate.from_hash(
          subject: csr.subject,
          issuer: @cert.subject,
          public_key: csr.public_key,
          good_for: good_for,
          extensions: extensions(subject_altnames)
        ).tap do |cert|
          cert.sign(@key, OpenSSL::Digest::SHA256.new)
        end
      end

      def verify(cert)
        cert.verify(@key)
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
