require 'openssl'
require 'securerandom'
require 'active_support/time'

# Conjur certificate authority, for issuing X509 certificates of
# Conjur machines (eg. followers, standbys, etc.).
module Authentication
  module AuthnK8s
    class CA

      class << self
        def generate_key
          OpenSSL::PKey::RSA.new 2048
        end

        # Generate a CA key and certificate.
        def generate(subject)
          key = generate_key
          public_key = key.public_key

          cert = Util::OpenSsl::X509::Certificate.from_hash(
            subject: subject,
            issuer: subject,
            public_key: public_key,
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
      end

      def initialize certs, key
        @bundle = certs
        @cacert = @bundle.first rescue @bundle
        @cakey = key
      end

      attr_reader :bundle

      # Issue a new certificate with the given key.
      #
      # @param name [String] CN of the client.
      # @param key [OpenSSL::PKey::RSA] key owned by the certificate holder, can
      # be just the public part. @see {.generate_key}
      # @return [OpenSSL::X509::Certificate]
      def issue(csr, subject_altnames)
        Certificate.new(@cacert, csr, subject_altnames).tap do |cert|
          cert.sign(@cakey, OpenSSL::Digest::SHA256.new)
        end
      end

      def verify cert
        cert.verify @cakey
      end

      # Encapsulates certificate setup logic
      class Certificate < OpenSSL::X509::Certificate
        attr_reader :cacert, :csr

        # +lifespan+ default is 3 days
        def initialize cacert, csr, subject_altnames, lifespan: 3 * 24 * 60 * 60
          super()

          @csr = csr
          @cacert = cacert

          self.version = 2
          self.serial = SecureRandom.random_number 2**160 # 20 bytes
          self.issuer = cacert.subject
          self.subject = csr.subject
          self.not_before = Time.now
          self.not_after = not_before + lifespan
          self.public_key = csr.public_key

          create_extension "keyUsage", "digitalSignature,keyEncipherment", true
          create_extension "subjectKeyIdentifier", "hash", false
          unless subject_altnames.empty?
            create_extension "subjectAltName", subject_altnames.join(','), false
          end
        end

        protected

        def ef
          @ef ||= OpenSSL::X509::ExtensionFactory.new.tap do |ef|
            ef.subject_certificate = self
            ef.issuer_certificate = cacert
          end
        end

        def create_extension *args
          add_extension ef.create_extension(*args)
        end
      end

    end
  end
end
